#include "shuzagram/mtproto/server_exchange.hpp"

#include <chrono>
#include <cstring>
#include <limits>

#include "crypto/bignum_util.hpp"
#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"
#include "shuzagram/mtproto/unexpected_encrypted_frame.hpp"

namespace shuzagram::mtproto {

namespace {

// The server never generates pq/dh_prime itself: this project (like the
// ShuzaGram production deployment) uses the same fixed values as gotd/td's
// own TestServerRNG -- see the header comment on FixedPq/FixedDhPrime and
// NOTES/transport-handshake-plan.md.
std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

UnencryptedMessage ReadHandshakeMessage(const ReadFrame& read) {
    const std::vector<std::uint8_t> frame = read();
    if (frame.size() >= 8) {
        std::array<std::uint8_t, 8> auth_key_id{};
        std::memcpy(auth_key_id.data(), frame.data(), 8);
        if (auth_key_id != std::array<std::uint8_t, 8>{}) {
            throw UnexpectedEncryptedFrameError(auth_key_id, frame);
        }
    }
    TLBuffer b;
    b.buf = frame;
    UnencryptedMessage msg;
    msg.Decode(b);
    // checkMsgID (exchange/proto.go): the server only ever expects
    // client-originated message ids here.
    if (MessageId::FromRaw(msg.message_id).Type() != MessageType::kFromClient) {
        throw std::runtime_error("handshake message has an unexpected message_id type");
    }
    return msg;
}

// Reads the next handshake message that ISN'T a plaintext msgs_ack,
// discarding any in between. Real clients (observed live: an Android
// Telegram fork) plaintext-acknowledge every server handshake reply
// (ResPQ, server_DH_params_ok) with msgs_ack#62d6b459 before sending their
// own next real message, sometimes batched into the same TCP segment as
// that next message. msgs_ack needs no reply and carries no handshake
// state, so every ReadHandshakeMessage call site in this exchange must go
// through this wrapper instead of calling it directly -- see
// NOTES/server-exchange-msgs-ack-plan.md (this is the second call site
// that needed it; the first one's own fix is what that note documents).
UnencryptedMessage ReadNextRealHandshakeMessage(const ReadFrame& read) {
    for (;;) {
        UnencryptedMessage msg = ReadHandshakeMessage(read);
        TLBuffer peek;
        peek.buf = msg.message_data;
        if (peek.PeekID() == messages::MsgsAck::kTypeId) continue;
        return msg;
    }
}

void WriteHandshakeMessage(const WriteFrame& write, MessageType type, const TLBuffer& payload) {
    UnencryptedMessage msg;
    msg.message_id = MessageId::New(std::chrono::system_clock::now(), type).Raw();
    msg.message_data = payload.buf;
    TLBuffer out;
    msg.Encode(out);
    write(out.buf);
}

// Port of compatServerRNG.GA / exchange/generator.go's TestServerRNG.GA:
// the one piece of the handshake that IS genuinely random per connection --
// the ephemeral DH secret `a` and its public share g_a = g^a mod dh_prime,
// resampled until g_a falls in the recommended safety range.
void GenerateGa(int g, const std::vector<std::uint8_t>& dh_prime, std::vector<std::uint8_t>& a,
                 std::vector<std::uint8_t>& g_a) {
    crypto::CheckGP(g, dh_prime);
    const std::vector<std::uint8_t> g_bytes = {static_cast<std::uint8_t>(g)};

    using crypto::detail::BytesToBignum;
    using crypto::detail::MakeBignum;
    crypto::detail::BignumPtr p = BytesToBignum(dh_prime);
    crypto::detail::BignumPtr one = MakeBignum();
    BN_one(one.get());
    crypto::detail::BignumPtr p_minus_one = MakeBignum();
    BN_sub(p_minus_one.get(), p.get(), one.get());
    crypto::detail::BignumPtr safety_min = MakeBignum();
    BN_set_word(safety_min.get(), 1);
    BN_lshift(safety_min.get(), safety_min.get(), crypto::kRsaKeyBits - 64);
    crypto::detail::BignumPtr safety_max = MakeBignum();
    BN_sub(safety_max.get(), p.get(), safety_min.get());

    for (;;) {
        a = crypto::SystemRandomBytes(crypto::kRsaByteLen); // uniform over [0, 2^2048)
        g_a = crypto::ModPow(g_bytes, a, dh_prime);
        crypto::detail::BignumPtr ga_bn = BytesToBignum(g_a);
        const bool in_range = BN_cmp(ga_bn.get(), one.get()) > 0 && BN_cmp(ga_bn.get(), p_minus_one.get()) < 0 &&
                               BN_cmp(ga_bn.get(), safety_min.get()) > 0 && BN_cmp(ga_bn.get(), safety_max.get()) < 0;
        if (in_range) return;
    }
}

} // namespace

std::vector<std::uint8_t> FixedPq() {
    // 0x17ED48941A08F981, exactly as compatServerRNG.PQ() / TestServerRNG.PQ()
    // return it (a real product of two ~32-bit primes, just not resampled
    // per connection in this deployment -- see the header comment).
    return {0x17, 0xED, 0x48, 0x94, 0x1A, 0x08, 0xF9, 0x81};
}

std::vector<std::uint8_t> FixedDhPrime() {
    return HexToBytes(
        "C71CAEB9C6B1C9048E6C522F70F13F73"
        "980D40238E3E21C14934D037563D930F"
        "48198A0AA7C14058229493D22530F4DB"
        "FA336F6E0AC925139543AED44CCE7C37"
        "20FD51F69458705AC68CD4FE6B6B13AB"
        "DC9746512969328454F18FAF8C595F64"
        "2477FE96BB2A941D5BCD1D4AC8CC4988"
        "0708FA9B378E3C4F3A9060BEE67CF9A4"
        "A4A695811051907E162753B56B0F6B41"
        "0DBA74D8A84B2A14B3144E0EF1284754"
        "FD17ED950D5965B4B9DD46582DB1178D"
        "169C6BC465B0D6FF9CA3928FEF5B9AE4"
        "E418FC15E83EBEA0F87FA9FF5EED7005"
        "0DED2849F47BF959D956850CE929851F"
        "0D8115F635B105EE2E4E15D04B2454BF"
        "6F4FADF034B10403119CD8E3B92FCC5B");
}

ServerExchangeResult ServerExchange::Run(const ReadFrame& read, const WriteFrame& write) {
    using namespace messages;

    // 1. Client sends req_pq(_multi). 2. Server replies with ResPQ. A fake
    // req_pq before the real req_DH_params is tolerated by looping back to
    // resend ResPQ with the retried nonce -- server_nonce/pq are generated
    // once, outside this loop (exchange/server_flow.go's `goto SendResPQ`
    // never touches either).
    ReqPq req;
    {
        const UnencryptedMessage first = ReadHandshakeMessage(read);
        TLBuffer b;
        b.buf = first.message_data;
        req.Decode(b);
    }

    Int128 server_nonce;
    {
        const auto random_bytes = crypto::SystemRandomBytes(16);
        std::copy(random_bytes.begin(), random_bytes.end(), server_nonce.begin());
    }
    const std::vector<std::uint8_t> pq = FixedPq();

    ReqDhParams dh_params;
    bool got_dh_params = false;
    while (!got_dh_params) {
        {
            ResPq res;
            res.nonce = req.nonce;
            res.server_nonce = server_nonce;
            res.pq = pq;
            res.server_public_key_fingerprints = {key_.Fingerprint()};
            TLBuffer payload;
            res.Encode(payload);
            WriteHandshakeMessage(write, MessageType::kServerResponse, payload);
        }

        // ReadNextRealHandshakeMessage already discards any plaintext
        // msgs_ack a real client sends acknowledging ResPQ (see its own
        // doc comment) -- resending ResQ stays reserved for an actual
        // retried req_pq(_multi) below, never triggered by an ack.
        const UnencryptedMessage next = ReadNextRealHandshakeMessage(read);
        TLBuffer b;
        b.buf = next.message_data;
        const std::uint32_t id = b.PeekID();
        if (id == kReqPqRequestTypeId || id == kReqPqMultiRequestTypeId) {
            req.Decode(b); // client resent a fake req_pq with a new nonce; loop and resend ResPQ
            continue;
        }
        dh_params.Decode(b);
        got_dh_params = true;
    }

    // 3. RSA_PAD-decrypt req_DH_params.encrypted_data, then TL-decode
    // whichever p_q_inner_data* variant is inside. dc/expires_in are
    // accepted but not validated: this deployment is single-backend, so
    // (matching internal/mtprotoedge/exchange_compat.go's documented
    // default) they're treated as opaque client routing labels, not an
    // identity or DC-mismatch check. A future StrictDC-equivalent mode is
    // out of scope here.
    PqInnerData inner;
    try {
        const std::vector<std::uint8_t> data_with_padding = crypto::RsaUnpad(dh_params.encrypted_data, key_);
        TLBuffer inner_buf;
        inner_buf.buf = data_with_padding;
        inner = PqInnerData::Decode(inner_buf);
    } catch (const std::exception& e) {
        throw ServerExchangeError(kCodeAuthKeyNotFound, std::string("decode req_DH_params: ") + e.what());
    }

    // p_q_inner_data_temp_dc's expires_in is the ONLY signal that decides
    // whether the resulting auth_key is temporary (PFS) or permanent; a
    // non-positive value would silently turn a temp-key request into a
    // permanent key, so it's rejected instead. Matches
    // internal/mtprotoedge/exchange_compat.go's validatePQInnerData.
    if (inner.kind == PqInnerDataKind::kTempDc && inner.expires_in <= 0) {
        throw ServerExchangeError(kCodeAuthKeyNotFound, "p_q_inner_data temporary key expires_in must be positive");
    }
    const auto handshake_time = std::chrono::system_clock::now();
    std::int64_t auth_key_expires_at = 0;
    if (inner.kind == PqInnerDataKind::kTempDc) {
        const std::int64_t now =
            std::chrono::duration_cast<std::chrono::seconds>(handshake_time.time_since_epoch()).count();
        auth_key_expires_at = now + static_cast<std::int64_t>(inner.expires_in);
        // TL timestamps are signed int32 on the wire -- reject an impossible
        // lifetime instead of silently wrapping a temporary key into what
        // would be read back as a permanent one (expires_at <= 0) or an
        // out-of-range one.
        if (auth_key_expires_at <= 0 || auth_key_expires_at > std::numeric_limits<std::int32_t>::max()) {
            throw ServerExchangeError(kCodeAuthKeyNotFound, "temporary auth key expiry is out of int32 range");
        }
    }

    // 4/5. Generate g_a (the real per-connection secret) and send
    // Server_DH_Params encrypted under TempAesKeys(new_nonce, server_nonce).
    const std::vector<std::uint8_t> dh_prime = FixedDhPrime();
    std::vector<std::uint8_t> a, g_a;
    GenerateGa(kDhGenerator, dh_prime, a, g_a);

    std::vector<std::uint8_t> temp_key, temp_iv;
    crypto::TempAesKeys(inner.new_nonce, server_nonce, temp_key, temp_iv);

    {
        ServerDhInnerData inner_data;
        inner_data.nonce = req.nonce;
        inner_data.server_nonce = server_nonce;
        inner_data.g = kDhGenerator;
        inner_data.dh_prime = dh_prime;
        inner_data.g_a = g_a;
        inner_data.server_time =
            static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count());
        TLBuffer inner_encoded;
        inner_data.Encode(inner_encoded);

        ServerDhParamsOk ok;
        ok.nonce = req.nonce;
        ok.server_nonce = server_nonce;
        ok.encrypted_answer = crypto::EncryptExchangeAnswer(inner_encoded.buf, temp_key, temp_iv);
        TLBuffer payload;
        ok.Encode(payload);
        WriteHandshakeMessage(write, MessageType::kServerResponse, payload);
    }

    // 6. Client replies with Set_client_DH_params carrying g_b.
    // ReadNextRealHandshakeMessage discards a plaintext msgs_ack
    // acknowledging server_DH_params_ok if one arrives first (same
    // real-client quirk as the req_DH_params wait above).
    SetClientDhParams client_params;
    {
        const UnencryptedMessage msg = ReadNextRealHandshakeMessage(read);
        TLBuffer b;
        b.buf = msg.message_data;
        client_params.Decode(b);
    }

    ClientDhInnerData client_inner;
    try {
        const std::vector<std::uint8_t> decrypted =
            crypto::DecryptExchangeAnswer(client_params.encrypted_data, temp_key, temp_iv);
        TLBuffer decrypted_buf;
        decrypted_buf.buf = decrypted;
        client_inner.Decode(decrypted_buf);
    } catch (const std::exception& e) {
        throw ServerExchangeError(kCodeAuthKeyNotFound, std::string("decrypt Set_client_DH_params: ") + e.what());
    }

    // 7. auth_key = g_b^a mod dh_prime. Note: unlike CheckDHParams (already
    // run implicitly on g/g_a via GenerateGa's own range check), the Go
    // source never range-checks the client-supplied g_b here before using
    // it -- ported faithfully as-is; see NOTES/transport-handshake-plan.md.
    ServerExchangeResult result;
    const std::vector<std::uint8_t> auth_key_bytes = crypto::ModPowFixed(client_inner.g_b, a, dh_prime, 256);
    std::copy(auth_key_bytes.begin(), auth_key_bytes.end(), result.auth_key.begin());
    result.server_salt = crypto::ServerSalt(inner.new_nonce, server_nonce);
    result.expires_at = static_cast<int>(auth_key_expires_at);

    // 8. dh_gen_ok proves both sides derived the same auth_key.
    {
        DhGenOk ok;
        ok.nonce = req.nonce;
        ok.server_nonce = server_nonce;
        ok.new_nonce_hash1 = crypto::NonceHash1(inner.new_nonce, result.auth_key);
        TLBuffer payload;
        ok.Encode(payload);
        WriteHandshakeMessage(write, MessageType::kServerResponse, payload);
    }

    return result;
}

} // namespace shuzagram::mtproto
