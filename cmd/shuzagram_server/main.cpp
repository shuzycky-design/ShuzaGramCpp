// The first actually-runnable service binary in this port: listens on a
// real TCP port, autodetects the wire transport per connection, runs the
// MTProto DH handshake, and persists the resulting auth_key to Postgres via
// the store layer built earlier. Everything after a successful handshake
// (RPC dispatch, sessions, update delivery) is not built yet -- the
// connection is simply closed once the auth_key is saved. See
// NOTES/tcp-wiring-plan.md for what's deliberately not here yet.
//
// Configuration is via environment variables (no config file/flags parser
// yet -- this is a first runnable slice, not the final entry point):
//   SHUZAGRAM_BIND_ADDRESS   default "0.0.0.0"
//   SHUZAGRAM_PORT           default 2398 (the port the real ShuzaGram
//                            deployment's TELESRV_SERVER_PORT uses)
//   SHUZAGRAM_RSA_KEY_PATH   default "./shuzagram-server-rsa.pem"
//   SHUZAGRAM_PG_DSN         libpq connection string; if unset, the server
//                            still runs the handshake but doesn't persist
//                            the resulting auth_key anywhere (logged only)
//   SHUZAGRAM_ADVERTISE_IP   default "127.0.0.1" -- the address help.getConfig
//                            tells clients to (re)connect to. SHUZAGRAM_BIND_ADDRESS
//                            (often 0.0.0.0, "listen on every interface") is
//                            never a valid value here -- a real deployment MUST
//                            override this to its actual reachable public IP.
//   SHUZAGRAM_DC_ID          default 1 -- this deployment's only DC id
//                            (single-backend, see NOTES/help-get-config-plan.md)
//   SHUZAGRAM_OTP_WEBHOOK_URL      unset by default -- with no URL, auth.sendCode
//                            keeps issuing the fixed "12345" dev code and
//                            delivers nothing (same as before this existed).
//                            Set to a real "OTP Webhook v1" endpoint (e.g.
//                            the already-deployed numbot container's own
//                            http://127.0.0.1:8080/otp) to deliver REAL
//                            random login codes over SMS -- see
//                            NOTES/otp-webhook-delivery-plan.md.
//   SHUZAGRAM_OTP_WEBHOOK_SECRET   HMAC-SHA256 signing secret; must match the
//                            receiving webhook's own configured secret.
//   SHUZAGRAM_OTP_WEBHOOK_TIMEOUT_MS  default 5000
//   SHUZAGRAM_OTP_CODE_LENGTH      default 5 -- digits in the delivered code
//                            (only used when a webhook URL is configured)

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>

#include "shuzagram/account/update_status.hpp"
#include "shuzagram/auth/bind_temp_auth_key.hpp"
#include "shuzagram/auth/check_password.hpp"
#include "shuzagram/auth/current_user.hpp"
#include "shuzagram/auth/sign_in.hpp"
#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/messages/auth.hpp"
#include "shuzagram/mtproto/messages/bind.hpp"
#include "shuzagram/mtproto/messages/bool.hpp"
#include "shuzagram/mtproto/messages/help.hpp"
#include "shuzagram/mtproto/messages/account.hpp"
#include "shuzagram/mtproto/messages/password.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/messages/users.hpp"
#include "shuzagram/mtproto/rpc_dispatch.hpp"
#include "shuzagram/mtproto/tcp_handshake_server.hpp"
#include "shuzagram/otpdelivery/webhook_sender.hpp"
#include "shuzagram/store/memory/code_store.hpp"
#include "shuzagram/store/postgres/auth_key_store.hpp"
#include "shuzagram/store/postgres/authorization_store.hpp"
#include "shuzagram/store/postgres/password_store.hpp"
#include "shuzagram/store/postgres/temp_auth_key_store.hpp"
#include "shuzagram/store/postgres/user_store.hpp"
#include "shuzagram/users/get_users.hpp"
#include "shuzagram/users/update_birthday.hpp"
#include "shuzagram/users/update_profile.hpp"
#include "shuzagram/users/username.hpp"

namespace {

std::string GetEnvOr(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

std::atomic<shuzagram::mtproto::TcpHandshakeServer*> g_server{nullptr};

void HandleShutdownSignal(int) {
    // Only touches an atomic pointer's Stop() (itself just an atomic
    // store) -- no allocation, no iostream, so this stays within what a
    // signal handler can safely do.
    if (auto* server = g_server.load()) server->Stop();
}

std::string HexEncode(const std::uint8_t* data, std::size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

std::vector<std::uint8_t> EncodeRpcError(int code, const std::string& message) {
    shuzagram::mtproto::messages::RpcError error;
    error.error_code = code;
    error.error_message = message;
    shuzagram::mtproto::TLBuffer out;
    error.Encode(out);
    return out.buf;
}

// auth.bindTempAuthKey handler. Registered only when Postgres is connected
// (auth_key_store/temp_key_store both need a live database); with no
// database this method falls through to the registry's usual
// METHOD_NOT_FOUND, same as every other unimplemented RPC method.
//
// db_mutex serializes every Postgres-touching operation this process
// performs (this and the handshake-completion Save() below): the store
// layer holds a single pqxx::connection (see store::postgres::Database's
// own doc comment -- a real connection pool is explicitly deferred), and
// pqxx::connection is not safe for concurrent use from the several
// per-connection worker threads TcpHandshakeServer::Run spawns. This trades
// away cross-connection DB concurrency for correctness; revisit once
// Database pools connections instead of holding just one.
std::vector<std::uint8_t> HandleAuthBindTempAuthKey(std::mutex& db_mutex, shuzagram::store::IAuthKeyStore& auth_keys,
                                                     shuzagram::store::ITempAuthKeyBindingStore& temp_keys,
                                                     shuzagram::mtproto::TLBuffer& body,
                                                     const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    mtproto::messages::AuthBindTempAuthKeyRequest req;
    req.DecodeBare(body);

    auth::BindTempAuthKeyRequest bind_req;
    bind_req.temp_auth_key_id = ctx.auth_key_id;
    bind_req.temp_session_id = ctx.session_id;
    bind_req.perm_auth_key_id = req.perm_auth_key_id;
    bind_req.nonce = req.nonce;
    bind_req.expires_at = req.expires_at;
    bind_req.encrypted_message = std::move(req.encrypted_message);

    try {
        std::lock_guard<std::mutex> lock(db_mutex);
        auth::BindTempAuthKey(auth_keys, temp_keys, bind_req);
    } catch (const auth::ExpiresAtInvalidError&) {
        return EncodeRpcError(400, "EXPIRES_AT_INVALID");
    } catch (const auth::TempAuthKeyEmptyError&) {
        return EncodeRpcError(400, "TEMP_AUTH_KEY_EMPTY");
    } catch (const auth::EncryptedMessageInvalidError&) {
        return EncodeRpcError(400, "ENCRYPTED_MESSAGE_INVALID");
    } catch (const store::TempAuthKeyAlreadyBoundError&) {
        return EncodeRpcError(400, "TEMP_AUTH_KEY_ALREADY_BOUND");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "auth.bindTempAuthKey internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }

    mtproto::TLBuffer out;
    mtproto::messages::EncodeBool(out, true);
    return out.buf;
}

// auth.sendCode. Always issues the fixed development code ("12345") --
// see auth::SendCode's own doc comment for why (no SMS/email provider is
// wired up in this project).
std::vector<std::uint8_t> HandleAuthSendCode(std::mutex& db_mutex, shuzagram::store::IUserStore& users,
                                              shuzagram::store::ICodeStore& codes,
                                              shuzagram::otpdelivery::WebhookSender* otp_sender, int code_length,
                                              shuzagram::mtproto::TLBuffer& body) {
    using namespace shuzagram;

    mtproto::messages::AuthSendCodeRequest req;
    req.DecodeBare(body);

    try {
        std::string hash;
        {
            std::lock_guard<std::mutex> lock(db_mutex);
            hash = auth::SendCode(users, codes, req.phone_number, "12345", otp_sender, code_length);
        }
        mtproto::messages::AuthSentCode resp;
        // With no OTP sender configured, SendCode issues the fixed 5-digit
        // dev code regardless of code_length -- report that real length,
        // not the configured one, so a real client's "enter N digits" UI
        // stays correct either way.
        resp.code_length = otp_sender ? code_length : 5;
        resp.phone_code_hash = hash;
        mtproto::TLBuffer out;
        resp.Encode(out);
        return out.buf;
    } catch (const auth::PhoneNumberInvalidError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const std::exception& e) {
        // Mirrors onAuthSendCode: the public error stays opaque (INTERNAL)
        // regardless of cause (store failure or OTP delivery failure) --
        // never leak the phone number or code into the response.
        std::fprintf(stderr, "auth.sendCode internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// auth.signIn. See auth::SignIn's doc comment: this connection's own
// auth_key_id (from RpcContext, not resolved from a bound temp key to its
// permanent identity -- that resolution layer isn't ported yet) is used
// directly as the Authorization's auth_key_id, so this only behaves
// correctly for a session on an already-permanent key.
std::vector<std::uint8_t> HandleAuthSignIn(std::mutex& db_mutex, shuzagram::store::IUserStore& users,
                                            shuzagram::store::IAuthorizationStore& authorizations,
                                            shuzagram::store::ICodeStore& codes,
                                            shuzagram::store::IPasswordStore& passwords,
                                            shuzagram::mtproto::TLBuffer& body,
                                            const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    mtproto::messages::AuthSignInRequest req;
    req.DecodeBare(body);

    domain::Authorization auth_template;
    auth_template.auth_key_id = ctx.auth_key_id;

    try {
        auth::SignInResult result;
        {
            std::lock_guard<std::mutex> lock(db_mutex);
            result = auth::SignIn(users, authorizations, codes, auth_template, req.phone_number, req.phone_code_hash,
                                   req.phone_code, &passwords);
        }
        mtproto::TLBuffer out;
        if (result.need_sign_up) {
            mtproto::messages::AuthAuthorizationSignUpRequired resp;
            resp.Encode(out);
        } else {
            mtproto::messages::AuthAuthorization resp;
            resp.user = result.user;
            resp.Encode(out);
        }
        return out.buf;
    } catch (const auth::SessionPasswordNeededError&) {
        // The authorization is already bound (password_pending=true) --
        // see that error's own doc comment. auth.checkPassword completes
        // the login from here.
        return EncodeRpcError(401, "SESSION_PASSWORD_NEEDED");
    } catch (const auth::CodeExpiredError&) {
        return EncodeRpcError(400, "PHONE_CODE_EXPIRED");
    } catch (const auth::CodeInvalidError&) {
        return EncodeRpcError(400, "PHONE_CODE_INVALID");
    } catch (const domain::AccountDeletedError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const domain::UserNotFoundError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const store::AuthKeyNotPermanentError&) {
        return EncodeRpcError(401, "AUTH_KEY_PERM_EMPTY");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "auth.signIn internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// auth.signUp. Same auth_key_id caveat as auth.signIn above.
std::vector<std::uint8_t> HandleAuthSignUp(std::mutex& db_mutex, shuzagram::store::IUserStore& users,
                                            shuzagram::store::IAuthorizationStore& authorizations,
                                            shuzagram::store::ICodeStore& codes, shuzagram::mtproto::TLBuffer& body,
                                            const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    mtproto::messages::AuthSignUpRequest req;
    req.DecodeBare(body);

    domain::Authorization auth_template;
    auth_template.auth_key_id = ctx.auth_key_id;

    try {
        domain::User created;
        {
            std::lock_guard<std::mutex> lock(db_mutex);
            created = auth::SignUp(users, authorizations, codes, auth_template, req.phone_number,
                                    req.phone_code_hash, req.first_name, req.last_name);
        }
        mtproto::messages::AuthAuthorization resp;
        resp.user = created;
        mtproto::TLBuffer out;
        resp.Encode(out);
        return out.buf;
    } catch (const auth::PhoneNumberInvalidError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const domain::FirstNameInvalidError&) {
        return EncodeRpcError(400, "FIRSTNAME_INVALID");
    } catch (const auth::CodeExpiredError&) {
        return EncodeRpcError(400, "PHONE_CODE_EXPIRED");
    } catch (const auth::CodeInvalidError&) {
        return EncodeRpcError(400, "PHONE_CODE_INVALID");
    } catch (const domain::AccountDeletedError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const domain::UserNotFoundError&) {
        return EncodeRpcError(406, "PHONE_NUMBER_INVALID");
    } catch (const store::AuthKeyNotPermanentError&) {
        return EncodeRpcError(401, "AUTH_KEY_PERM_EMPTY");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "auth.signUp internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.getPassword. Works even before/without a bound authorization
// (defaultPasswordSettings(), has_password=false) -- a session mid-login
// (e.g. right after SESSION_PASSWORD_NEEDED) still needs to call this to
// learn the salts/srp_B to build its auth.checkPassword proof against.
std::vector<std::uint8_t> HandleAccountGetPassword(std::mutex& db_mutex,
                                                    shuzagram::store::IAuthorizationStore& authorizations,
                                                    shuzagram::store::IPasswordStore& passwords,
                                                    shuzagram::mtproto::TLBuffer& body,
                                                    const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    mtproto::messages::AccountGetPasswordRequest req;
    req.DecodeBare(body);

    try {
        std::lock_guard<std::mutex> lock(db_mutex);
        const auto authz = authorizations.ByAuthKey(ctx.auth_key_id);
        const domain::PasswordSettings settings = (authz && authz->user_id != 0)
                                                       ? auth::GetPassword(passwords, authz->user_id)
                                                       : auth::DefaultPasswordSettings();

        mtproto::messages::AccountPassword resp;
        resp.settings = settings;
        mtproto::TLBuffer out;
        resp.Encode(out);
        return out.buf;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.getPassword internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// auth.checkPassword. Also completes a pending SESSION_PASSWORD_NEEDED
// login (MarkPasswordPassed), exactly like the Go source's
// onAuthCheckPassword.
std::vector<std::uint8_t> HandleAuthCheckPassword(std::mutex& db_mutex, shuzagram::store::IUserStore& users,
                                                   shuzagram::store::IAuthorizationStore& authorizations,
                                                   shuzagram::store::IPasswordStore& passwords,
                                                   shuzagram::mtproto::TLBuffer& body,
                                                   const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    mtproto::messages::AuthCheckPasswordRequest req;
    req.DecodeBare(body);

    try {
        std::lock_guard<std::mutex> lock(db_mutex);
        const auto authz = authorizations.ByAuthKey(ctx.auth_key_id);
        if (!authz || authz->user_id == 0) return EncodeRpcError(400, "PASSWORD_HASH_INVALID");

        auth::CheckPassword(passwords, authz->user_id, req.check);

        if (authz->password_pending) {
            authorizations.MarkPasswordPassed(ctx.auth_key_id, authz->user_id);
        }

        const auto user = users.ByID(authz->user_id);
        mtproto::messages::AuthAuthorization resp;
        if (user) resp.user = *user;
        mtproto::TLBuffer out;
        resp.Encode(out);
        return out.buf;
    } catch (const auth::PasswordHashInvalidError&) {
        return EncodeRpcError(400, "PASSWORD_HASH_INVALID");
    } catch (const auth::SrpIdInvalidError&) {
        return EncodeRpcError(400, "SRP_ID_INVALID");
    } catch (const auth::SrpPasswordChangedError&) {
        return EncodeRpcError(400, "SRP_PASSWORD_CHANGED");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "auth.checkPassword internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// users.getUsers. Resolves inputUserSelf/inputUser against whichever user_id
// (if any) authorization_store has bound to this connection's auth_key_id --
// see users::ResolveGetUsers for the faithful port of onUsersGetUsers, and
// messages/users.hpp's EncodeUser for exactly which of the real user# TL
// constructor's many optional fields this port actually fills in.
std::vector<std::uint8_t> HandleUsersGetUsers(shuzagram::store::IAuthorizationStore& authorizations,
                                               shuzagram::store::IUserStore& users,
                                               shuzagram::mtproto::TLBuffer& body,
                                               const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::UsersGetUsersRequest req;
        req.DecodeBare(body);

        const auto resolved = shuzagram::users::ResolveGetUsers(authorizations, users, ctx.auth_key_id, req.ids);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();

        mtproto::TLBuffer out;
        out.PutVectorHeader(static_cast<std::int32_t>(resolved.size()));
        for (const auto& r : resolved) {
            mtproto::messages::EncodeUser(out, r.user, r.self, now);
        }
        return out.buf;
    } catch (const std::exception& e) {
        // Covers domain::NotImplementedError from an inputUserFromMessage
        // entry (see InputUser::Decode) as well as any store failure -- both
        // are internal gaps/faults, never a client-correctable input error.
        std::fprintf(stderr, "users.getUsers internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.updateStatus. Always answers boolTrue, exactly like the real
// onAccountUpdateStatus (even an unauthorized/password-pending caller gets
// true back -- it's a deliberate no-op there, never an error). See
// account::UpdateStatus's doc comment for what's cut relative to the Go
// source (live presence push, write debounce).
std::vector<std::uint8_t> HandleAccountUpdateStatus(shuzagram::store::IAuthorizationStore& authorizations,
                                                     shuzagram::store::IUserStore& users,
                                                     shuzagram::mtproto::TLBuffer& body,
                                                     const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountUpdateStatusRequest req;
        req.DecodeBare(body);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        account::UpdateStatus(authorizations, users, ctx.auth_key_id, static_cast<int>(now));

        mtproto::TLBuffer out;
        mtproto::messages::EncodeBool(out, true);
        return out.buf;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.updateStatus internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.getAuthorizations. An unauthorized/password-pending caller gets an
// empty list back, matching onAccountGetAuthorizations's own outcome (it
// doesn't check the authorized bool at all, but queries with user_id 0,
// which no real authorization row ever has -- same observable result
// without the pointless store round-trip). See messages/account.hpp's
// EncodeAuthorization for the branding-field simplification.
std::vector<std::uint8_t> HandleAccountGetAuthorizations(shuzagram::store::IAuthorizationStore& authorizations,
                                                          shuzagram::mtproto::TLBuffer& body,
                                                          const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountGetAuthorizationsRequest req;
        req.DecodeBare(body);

        const auto current = auth::ResolveCurrentUser(authorizations, ctx.auth_key_id);
        std::vector<domain::Authorization> list;
        if (current.authorized) list = authorizations.ListByUser(current.user_id);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();

        mtproto::TLBuffer out;
        mtproto::messages::EncodeAccountAuthorizations(out, list, ctx.auth_key_id, now);
        return out.buf;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.getAuthorizations internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.updateProfile. Response is a plain user# (self=true, since it's
// always the caller's own account) -- reuses EncodeUser from
// messages/users.hpp rather than duplicating the projection.
std::vector<std::uint8_t> HandleAccountUpdateProfile(shuzagram::store::IAuthorizationStore& authorizations,
                                                      shuzagram::store::IUserStore& users,
                                                      shuzagram::mtproto::TLBuffer& body,
                                                      const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountUpdateProfileRequest req;
        req.DecodeBare(body);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        const auto current = auth::ResolveCurrentUser(authorizations, ctx.auth_key_id);
        const auto updated = shuzagram::users::UpdateProfile(users, current.user_id, req.update, now);

        mtproto::TLBuffer out;
        mtproto::messages::EncodeUser(out, updated, /*is_self=*/true, now);
        return out.buf;
    } catch (const domain::FirstNameInvalidError&) {
        return EncodeRpcError(400, "FIRSTNAME_INVALID");
    } catch (const domain::AboutTooLongError&) {
        return EncodeRpcError(400, "ABOUT_TOO_LONG");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.updateProfile internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.checkUsername.
std::vector<std::uint8_t> HandleAccountCheckUsername(shuzagram::store::IAuthorizationStore& authorizations,
                                                      shuzagram::store::IUserStore& users,
                                                      shuzagram::mtproto::TLBuffer& body,
                                                      const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountCheckUsernameRequest req;
        req.DecodeBare(body);

        const auto current = auth::ResolveCurrentUser(authorizations, ctx.auth_key_id);
        const bool available = shuzagram::users::CheckUsername(users, current.user_id, req.username);

        mtproto::TLBuffer out;
        mtproto::messages::EncodeBool(out, available);
        return out.buf;
    } catch (const domain::UsernameInvalidError&) {
        return EncodeRpcError(400, "USERNAME_INVALID");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.checkUsername internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.updateUsername.
std::vector<std::uint8_t> HandleAccountUpdateUsername(shuzagram::store::IAuthorizationStore& authorizations,
                                                       shuzagram::store::IUserStore& users,
                                                       shuzagram::mtproto::TLBuffer& body,
                                                       const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountUpdateUsernameRequest req;
        req.DecodeBare(body);

        const auto current = auth::ResolveCurrentUser(authorizations, ctx.auth_key_id);
        const auto updated = shuzagram::users::UpdateUsername(users, current.user_id, req.username);

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        mtproto::TLBuffer out;
        mtproto::messages::EncodeUser(out, updated, /*is_self=*/true, now);
        return out.buf;
    } catch (const domain::UsernameInvalidError&) {
        return EncodeRpcError(400, "USERNAME_INVALID");
    } catch (const domain::UsernameOccupiedError&) {
        return EncodeRpcError(400, "USERNAME_OCCUPIED");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.updateUsername internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// account.updateBirthday.
std::vector<std::uint8_t> HandleAccountUpdateBirthday(shuzagram::store::IAuthorizationStore& authorizations,
                                                       shuzagram::store::IUserStore& users,
                                                       shuzagram::mtproto::TLBuffer& body,
                                                       const shuzagram::mtproto::RpcContext& ctx) {
    using namespace shuzagram;

    try {
        mtproto::messages::AccountUpdateBirthdayRequest req;
        req.DecodeBare(body);

        const auto current = auth::ResolveCurrentUser(authorizations, ctx.auth_key_id);
        shuzagram::users::UpdateBirthday(users, current.user_id, req.birthday);

        mtproto::TLBuffer out;
        mtproto::messages::EncodeBool(out, true);
        return out.buf;
    } catch (const domain::BirthdayInvalidError&) {
        return EncodeRpcError(400, "BIRTHDAY_INVALID");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "account.updateBirthday internal error: %s\n", e.what());
        return EncodeRpcError(500, "INTERNAL");
    }
}

// help.getConfig. Deliberately registered unconditionally (not gated
// behind Postgres being connected, unlike every auth.* handler above): the
// real protocol allows this even on a connection that never logs in, and
// it needs no store at all -- see messages/help.hpp for exactly which
// values are faithfully copied from the Go source's BuildConfig versus
// left at their zero/unset state.
std::vector<std::uint8_t> HandleHelpGetConfig(int dc_id, const std::string& advertise_ip, int advertise_port,
                                               shuzagram::mtproto::TLBuffer& body) {
    using namespace shuzagram;

    mtproto::messages::HelpGetConfigRequest req;
    req.DecodeBare(body);

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    mtproto::messages::Config config;
    config.dc = dc_id;
    config.ip_address = advertise_ip;
    config.port = advertise_port;
    config.date = now;
    config.expires = now + 3600; // matches BuildConfig's now.Add(time.Hour)

    mtproto::TLBuffer out;
    config.Encode(out);
    return out.buf;
}

} // namespace

int main() {
    using namespace shuzagram;

    const std::string bind_address = GetEnvOr("SHUZAGRAM_BIND_ADDRESS", "0.0.0.0");
    const int port = std::atoi(GetEnvOr("SHUZAGRAM_PORT", "2398").c_str());
    const std::string rsa_key_path = GetEnvOr("SHUZAGRAM_RSA_KEY_PATH", "./shuzagram-server-rsa.pem");
    const std::string pg_dsn = GetEnvOr("SHUZAGRAM_PG_DSN", "");
    const std::string advertise_ip = GetEnvOr("SHUZAGRAM_ADVERTISE_IP", "127.0.0.1");
    const int dc_id = std::atoi(GetEnvOr("SHUZAGRAM_DC_ID", "1").c_str());
    const std::string otp_webhook_url = GetEnvOr("SHUZAGRAM_OTP_WEBHOOK_URL", "");
    const int otp_code_length = std::atoi(GetEnvOr("SHUZAGRAM_OTP_CODE_LENGTH", "5").c_str());

    std::unique_ptr<otpdelivery::WebhookSender> otp_sender;
    if (!otp_webhook_url.empty()) {
        otpdelivery::WebhookSender::Config config;
        config.url = otp_webhook_url;
        config.secret = GetEnvOr("SHUZAGRAM_OTP_WEBHOOK_SECRET", "");
        config.timeout =
            std::chrono::milliseconds(std::atoi(GetEnvOr("SHUZAGRAM_OTP_WEBHOOK_TIMEOUT_MS", "5000").c_str()));
        otp_sender = std::make_unique<otpdelivery::WebhookSender>(config);
        std::printf("OTP webhook delivery configured: %s (real login codes will be sent for auth.sendCode)\n",
                    otp_webhook_url.c_str());
    } else {
        std::printf("SHUZAGRAM_OTP_WEBHOOK_URL not set -- auth.sendCode will keep issuing the fixed dev code\n");
    }

    mtproto::crypto::RsaPrivateKey key = [&] {
        try {
            return mtproto::crypto::RsaPrivateKey::LoadOrGenerate(rsa_key_path);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "failed to load/generate RSA key at %s: %s\n", rsa_key_path.c_str(), e.what());
            std::exit(1);
        }
    }();
    std::printf("RSA key ready (%s), fingerprint=%llx\n", rsa_key_path.c_str(),
                static_cast<unsigned long long>(key.Fingerprint()));

    std::mutex db_mutex; // see HandleAuthBindTempAuthKey's doc comment
    std::unique_ptr<store::postgres::Database> db;
    std::unique_ptr<store::postgres::AuthKeyStore> auth_key_store;
    std::unique_ptr<store::postgres::TempAuthKeyBindingStore> temp_key_store;
    std::unique_ptr<store::postgres::UserStore> user_store;
    std::unique_ptr<store::postgres::AuthorizationStore> authorization_store;
    std::unique_ptr<store::postgres::PasswordStore> password_store;
    store::memory::CodeStore code_store; // see its own doc comment: real, not just a test double
    if (!pg_dsn.empty()) {
        try {
            db = std::make_unique<store::postgres::Database>(pg_dsn);
            auth_key_store = std::make_unique<store::postgres::AuthKeyStore>(*db);
            temp_key_store = std::make_unique<store::postgres::TempAuthKeyBindingStore>(*db);
            user_store = std::make_unique<store::postgres::UserStore>(*db);
            authorization_store = std::make_unique<store::postgres::AuthorizationStore>(*db);
            password_store = std::make_unique<store::postgres::PasswordStore>(*db);
            std::printf("connected to Postgres; completed handshakes will persist their auth_key\n");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "failed to connect to Postgres (%s): %s -- continuing without persistence\n",
                         pg_dsn.c_str(), e.what());
        }
    } else {
        std::printf("SHUZAGRAM_PG_DSN not set -- completed handshakes will be logged but not persisted\n");
    }

    mtproto::RpcHandlerRegistry rpc_registry;
    rpc_registry.Register(mtproto::messages::HelpGetConfigRequest::kTypeId,
                           [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext&) {
                               return HandleHelpGetConfig(dc_id, advertise_ip, port, body);
                           });
    std::printf("help.getConfig is wired up (advertising %s:%d as DC %d)\n", advertise_ip.c_str(), port, dc_id);
    if (auth_key_store && temp_key_store) {
        rpc_registry.Register(mtproto::messages::AuthBindTempAuthKeyRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAuthBindTempAuthKey(db_mutex, *auth_key_store, *temp_key_store, body,
                                                                     ctx);
                               });
        std::printf("auth.bindTempAuthKey is wired up\n");
    }
    if (user_store && authorization_store && password_store) {
        rpc_registry.Register(mtproto::messages::AuthSendCodeRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext&) {
                                   return HandleAuthSendCode(db_mutex, *user_store, code_store, otp_sender.get(),
                                                              otp_code_length, body);
                               });
        rpc_registry.Register(mtproto::messages::AuthSignInRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAuthSignIn(db_mutex, *user_store, *authorization_store, code_store,
                                                            *password_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AuthSignUpRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAuthSignUp(db_mutex, *user_store, *authorization_store, code_store,
                                                            body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountGetPasswordRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountGetPassword(db_mutex, *authorization_store, *password_store,
                                                                    body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AuthCheckPasswordRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAuthCheckPassword(db_mutex, *user_store, *authorization_store,
                                                                   *password_store, body, ctx);
                               });
        std::printf("auth.sendCode/auth.signIn/auth.signUp/account.getPassword/auth.checkPassword are wired up "
                    "(dev fixed code only)\n");
    }
    if (user_store && authorization_store) {
        rpc_registry.Register(mtproto::messages::UsersGetUsersRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleUsersGetUsers(*authorization_store, *user_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountUpdateStatusRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountUpdateStatus(*authorization_store, *user_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountGetAuthorizationsRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountGetAuthorizations(*authorization_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountUpdateProfileRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountUpdateProfile(*authorization_store, *user_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountCheckUsernameRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountCheckUsername(*authorization_store, *user_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountUpdateUsernameRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountUpdateUsername(*authorization_store, *user_store, body, ctx);
                               });
        rpc_registry.Register(mtproto::messages::AccountUpdateBirthdayRequest::kTypeId,
                               [&](std::uint32_t, mtproto::TLBuffer& body, const mtproto::RpcContext& ctx) {
                                   return HandleAccountUpdateBirthday(*authorization_store, *user_store, body, ctx);
                               });
        std::printf("users.getUsers/account.updateStatus/account.getAuthorizations/"
                    "account.updateProfile/account.checkUsername/account.updateUsername/"
                    "account.updateBirthday are wired up\n");
    }

    // A real client that already holds an auth key for this server (from an
    // earlier connection) skips the handshake on reconnect and sends an
    // encrypted frame straight away -- without this, TcpHandshakeServer has
    // no way to serve that connection and just drops it (see
    // UnexpectedEncryptedFrameError's header comment). All validity rules
    // (existence, expiry, migration-artifact rejection) live here, not in
    // TcpHandshakeServer, per its own doc comment.
    mtproto::TcpHandshakeServer::AuthKeyResolver auth_key_resolver;
    if (auth_key_store) {
        auth_key_resolver =
            [&](const std::array<std::uint8_t, 8>& id) -> std::optional<mtproto::ResolvedAuthKey> {
            std::optional<store::AuthKeyData> data;
            try {
                std::lock_guard<std::mutex> lock(db_mutex);
                data = auth_key_store->Get(id);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "auth_key lookup for resumed session failed: %s\n", e.what());
                return std::nullopt;
            }
            if (!data) return std::nullopt;
            // expires_at == -1: an unprovable migration-era row -- must be
            // rejected (see AuthKeyData::expires_at's own doc comment).
            if (data->expires_at < 0) return std::nullopt;
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();
            if (data->expires_at > 0 && data->expires_at <= now) return std::nullopt; // expired temporary key
            mtproto::ResolvedAuthKey resolved;
            resolved.auth_key = data->value;
            resolved.server_salt = data->server_salt;
            return resolved;
        };
    }

    mtproto::TcpHandshakeServer server(bind_address, static_cast<std::uint16_t>(port), std::move(key), &rpc_registry,
                                        auth_key_resolver);
    std::printf("listening on %s:%d\n", bind_address.c_str(), server.Port());

    g_server.store(&server);
    std::signal(SIGINT, HandleShutdownSignal);
    std::signal(SIGTERM, HandleShutdownSignal);

    server.Run(
        [&](const mtproto::ServerExchangeResult& result) {
            const auto auth_key_id = mtproto::crypto::AuthKeyId(result.auth_key);
            std::printf("handshake completed: auth_key_id=%s server_salt=%lld\n",
                        HexEncode(auth_key_id.data(), auth_key_id.size()).c_str(),
                        static_cast<long long>(result.server_salt));
            if (!auth_key_store) return;
            try {
                store::AuthKeyData data;
                data.id = auth_key_id;
                data.value = result.auth_key;
                data.server_salt = result.server_salt;
                data.expires_at = result.expires_at; // 0 = permanent, >0 = temporary (PFS) key
                std::lock_guard<std::mutex> lock(db_mutex);
                auth_key_store->Save(data);
                std::printf("  saved to Postgres\n");
            } catch (const std::exception& e) {
                std::fprintf(stderr, "  failed to persist auth_key: %s\n", e.what());
            }
        },
        [](const std::string& what) { std::fprintf(stderr, "handshake failed: %s\n", what.c_str()); });

    std::printf("shutting down\n");
    std::fflush(stdout);
    // std::_Exit(), not return: the Ubuntu libpqxx 7.10.0 package double-frees a
    // static string during global destruction -- reproducible with a ~10-line
    // program that does nothing but construct a pqxx::connection, and present
    // here even when SHUZAGRAM_PG_DSN was never set, since linking
    // shuzagram_store_postgres alone is enough to register the bad destructor.
    // _Exit() skips static destructors entirely, which is safe here (the
    // process is terminating and the OS reclaims everything) but is not a fix;
    // see the identical note in tests/user_store_smoke.cpp and
    // NOTES/architecture-overview.md.
    std::_Exit(0);
}
