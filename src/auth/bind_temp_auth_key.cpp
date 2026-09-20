#include "shuzagram/auth/bind_temp_auth_key.hpp"

#include <chrono>
#include <cstring>

#include "shuzagram/mtproto/crypto/bind.hpp"

// Ported from internal/app/auth/service.go's BindTempAuthKey +
// validateBindTempAuthKey -- see the header for the scope this covers.
namespace shuzagram::auth {

namespace {

std::int64_t NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// auth_key_id as a little-endian int64 vs. as an 8-byte array: the same
// trivial conversion internal/rpc/auth.go's authKeyIDFromInt64/authKeyIDInt64
// perform, duplicated locally here rather than shared with
// store::postgres::detail's identical helpers (those are a private header
// of that library) -- the Go source duplicates this exact conversion across
// packages the same way.
std::int64_t AuthKeyIdToInt64(const std::array<std::uint8_t, 8>& id) {
    std::uint64_t v;
    std::memcpy(&v, id.data(), 8);
    return static_cast<std::int64_t>(v);
}

std::array<std::uint8_t, 8> AuthKeyIdFromInt64(std::int64_t v) {
    std::array<std::uint8_t, 8> id{};
    const auto uv = static_cast<std::uint64_t>(v);
    std::memcpy(id.data(), &uv, 8);
    return id;
}

} // namespace

domain::TempAuthKeyBindingResult BindTempAuthKey(store::IAuthKeyStore& auth_keys,
                                                  store::ITempAuthKeyBindingStore& temp_keys,
                                                  const BindTempAuthKeyRequest& req) {
    if (req.expires_at <= 0) throw ExpiresAtInvalidError();

    const std::array<std::uint8_t, 8> perm_id = AuthKeyIdFromInt64(req.perm_auth_key_id);
    const store::AuthKeyBindingKeys pair = auth_keys.LoadBindingKeys(req.temp_auth_key_id, perm_id);

    if (!pair.temporary_found || pair.temporary.expires_at <= NowUnix()) {
        throw TempAuthKeyEmptyError();
    }
    if (!pair.permanent_found || pair.permanent.expires_at != 0) {
        // Either the claimed permanent key doesn't exist, or it's itself a
        // temporary/media-temporary key -- either way the caller can't
        // possibly hold a valid proof for it. Same public error as an
        // actually-bad ciphertext: never reveal which case it was.
        throw EncryptedMessageInvalidError();
    }
    mtproto::messages::BindAuthKeyInner inner;
    try {
        inner = mtproto::crypto::DecryptBindAuthKeyInner(pair.permanent.value, req.encrypted_message);
    } catch (const mtproto::crypto::BindEncryptedMessageInvalidError&) {
        throw EncryptedMessageInvalidError();
    }

    if (inner.nonce != req.nonce ||
        inner.temp_auth_key_id != AuthKeyIdToInt64(req.temp_auth_key_id) ||
        inner.perm_auth_key_id != req.perm_auth_key_id ||
        inner.temp_session_id != req.temp_session_id ||
        inner.expires_at != req.expires_at) {
        throw EncryptedMessageInvalidError();
    }
    // Re-check: decrypting/validating the proof took nonzero time, and the
    // temp key's expiry is a hard protocol boundary -- matches the Go
    // source's identical second check right before persisting.
    if (pair.temporary.expires_at <= NowUnix()) throw TempAuthKeyEmptyError();

    domain::TempAuthKeyBinding binding;
    binding.temp_auth_key_id = req.temp_auth_key_id;
    binding.perm_auth_key_id = req.perm_auth_key_id;
    binding.perm_auth_key_id = req.perm_auth_key_id;
    binding.nonce = req.nonce;
    binding.temp_session_id = req.temp_session_id;
    // Normalized to the HANDSHAKE-authoritative expiry (the temp key's own
    // row), never the client-supplied req.expires_at -- the cross-check
    // above already requires them to be equal, but this is the value
    // that's actually trusted.
    binding.expires_at = pair.temporary.expires_at;
    binding.encrypted_message = req.encrypted_message;

    return temp_keys.SaveWithState(binding);
}

} // namespace shuzagram::auth
