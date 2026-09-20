// A real client that already holds an auth key for this server (from an
// earlier connection) skips the handshake entirely on reconnect and sends
// an encrypted frame straight away. ServerExchange can't process that
// itself -- it throws UnexpectedEncryptedFrameError, which
// tcp_handshake_server.cpp must resolve out-of-band (via
// TcpHandshakeServer::AuthKeyResolver) rather than treating it as a broken
// handshake. This test proves both branches over a real TCP socket: (1) a
// SECOND, fresh connection that skips the handshake and sends an encrypted
// ping straight away gets served using the resolved key, and (2) an
// unknown auth_key_id gets a bare -404 protocol-error frame instead of the
// connection just hanging.

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <map>
#include <mutex>
#include <random>
#include <thread>

#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/rpc_dispatch.hpp"
#include "shuzagram/mtproto/tcp_handshake_server.hpp"
#include "shuzagram/mtproto/transport/codec.hpp"
#include "shuzagram/mtproto/transport/intermediate_codec.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"
#include "shuzagram/net/tcp_socket.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::transport;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (ok) {
        std::printf("ok: %s\n", what.c_str());
    } else {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// --- same test-only pq factorization as the other end-to-end tests ---
std::uint64_t MulMod(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
    return static_cast<std::uint64_t>((static_cast<unsigned __int128>(a) * b) % m);
}
std::uint64_t Gcd(std::uint64_t a, std::uint64_t b) {
    while (b != 0) {
        const std::uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}
std::pair<std::uint64_t, std::uint64_t> DecomposePq(std::uint64_t pq, std::mt19937_64& rng) {
    const std::uint64_t what = pq;
    std::uint64_t g = 0;
    int i = 0;
    while (!(g > 1 && g < what)) {
        std::uint64_t v = (rng() & 15) + 17;
        v %= what;
        std::uint64_t x = rng() % (what - 1) + 1;
        std::uint64_t y = x;
        const int lim = 1 << (i + 18);
        int j = 1;
        bool flag = true;
        while (j < lim && flag) {
            x = (MulMod(x, x, what) + v) % what;
            const std::uint64_t z = (x < y) ? (what - y + x) : (x - y);
            g = Gcd(z, what);
            if ((j & (j - 1)) == 0) y = x;
            ++j;
            if (g != 1) flag = false;
        }
        ++i;
    }
    std::uint64_t p = g;
    std::uint64_t q = what / g;
    if (p > q) std::swap(p, q);
    return {p, q};
}
std::uint64_t BytesToU64(const std::vector<std::uint8_t>& b) {
    std::uint64_t v = 0;
    for (const auto byte : b) v = (v << 8) | byte;
    return v;
}
std::vector<std::uint8_t> U64ToMinimalBytes(std::uint64_t v) {
    std::vector<std::uint8_t> out;
    bool started = false;
    for (int i = 7; i >= 0; --i) {
        const auto byte = static_cast<std::uint8_t>(v >> (8 * i));
        if (byte != 0) started = true;
        if (started) out.push_back(byte);
    }
    if (out.empty()) out.push_back(0);
    return out;
}
Int128 RandomInt128() {
    Int128 out{};
    const auto r = crypto::SystemRandomBytes(16);
    std::copy(r.begin(), r.end(), out.begin());
    return out;
}
Int256 RandomInt256() {
    Int256 out{};
    const auto r = crypto::SystemRandomBytes(32);
    std::copy(r.begin(), r.end(), out.begin());
    return out;
}

struct HandshakeResult {
    std::array<std::uint8_t, 256> auth_key{};
    std::int64_t server_salt = 0;
};

HandshakeResult RunHandshake(shuzagram::net::TcpSocket& socket, IntermediateCodec& codec,
                              const crypto::RsaPublicKey& server_key, std::mt19937_64& rng) {
    using namespace messages;

    auto send = [&](MessageType type, const TLBuffer& payload) {
        UnencryptedMessage msg;
        msg.message_id = MessageId::New(std::chrono::system_clock::now(), type).Raw();
        msg.message_data = payload.buf;
        TLBuffer framed;
        msg.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);
    };
    auto recv = [&]() -> TLBuffer {
        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(b);
        TLBuffer payload;
        payload.buf = msg.message_data;
        return payload;
    };

    const Int128 nonce = RandomInt128();
    {
        TLBuffer payload;
        payload.PutID(kReqPqMultiRequestTypeId);
        payload.PutInt128(nonce);
        send(MessageType::kFromClient, payload);
    }

    ResPq res;
    {
        TLBuffer b = recv();
        b.ConsumeID(ResPq::kTypeId);
        res.nonce = b.GetInt128();
        res.server_nonce = b.GetInt128();
        res.pq = b.GetBytes();
        const auto count = b.VectorHeader();
        for (int i = 0; i < count; ++i) res.server_public_key_fingerprints.push_back(b.Long());
    }

    const auto [p, q] = DecomposePq(BytesToU64(res.pq), rng);
    const auto p_bytes = U64ToMinimalBytes(p);
    const auto q_bytes = U64ToMinimalBytes(q);
    const Int256 new_nonce = RandomInt256();

    std::vector<std::uint8_t> encrypted_data;
    {
        TLBuffer inner_encoded;
        inner_encoded.PutID(PqInnerData::kPlainTypeId);
        inner_encoded.PutBytes(res.pq);
        inner_encoded.PutBytes(p_bytes);
        inner_encoded.PutBytes(q_bytes);
        inner_encoded.PutInt128(res.nonce);
        inner_encoded.PutInt128(res.server_nonce);
        inner_encoded.PutInt256(new_nonce);
        encrypted_data = crypto::RsaPad(inner_encoded.buf, server_key);
    }
    {
        TLBuffer payload;
        payload.PutID(ReqDhParams::kTypeId);
        payload.PutInt128(res.nonce);
        payload.PutInt128(res.server_nonce);
        payload.PutBytes(p_bytes);
        payload.PutBytes(q_bytes);
        payload.PutLong(res.server_public_key_fingerprints.at(0));
        payload.PutBytes(encrypted_data);
        send(MessageType::kFromClient, payload);
    }

    ServerDhParamsOk ok;
    {
        TLBuffer b = recv();
        b.ConsumeID(ServerDhParamsOk::kTypeId);
        ok.nonce = b.GetInt128();
        ok.server_nonce = b.GetInt128();
        ok.encrypted_answer = b.GetBytes();
    }

    std::vector<std::uint8_t> temp_key, temp_iv;
    crypto::TempAesKeys(new_nonce, res.server_nonce, temp_key, temp_iv);

    ServerDhInnerData server_inner;
    {
        const auto decrypted = crypto::DecryptExchangeAnswer(ok.encrypted_answer, temp_key, temp_iv);
        TLBuffer b;
        b.buf = decrypted;
        b.ConsumeID(ServerDhInnerData::kTypeId);
        server_inner.nonce = b.GetInt128();
        server_inner.server_nonce = b.GetInt128();
        server_inner.g = b.Int();
        server_inner.dh_prime = b.GetBytes();
        server_inner.g_a = b.GetBytes();
        server_inner.server_time = b.Int();
    }

    const std::vector<std::uint8_t> client_secret_b = crypto::SystemRandomBytes(256);
    const std::vector<std::uint8_t> g_bytes = {static_cast<std::uint8_t>(server_inner.g)};
    const auto g_b = crypto::ModPow(g_bytes, client_secret_b, server_inner.dh_prime);

    HandshakeResult result;
    const auto auth_key_bytes = crypto::ModPowFixed(server_inner.g_a, client_secret_b, server_inner.dh_prime, 256);
    std::copy(auth_key_bytes.begin(), auth_key_bytes.end(), result.auth_key.begin());
    result.server_salt = crypto::ServerSalt(new_nonce, res.server_nonce);

    {
        ClientDhInnerData client_inner;
        client_inner.nonce = res.nonce;
        client_inner.server_nonce = res.server_nonce;
        client_inner.retry_id = 0;
        client_inner.g_b = g_b;
        TLBuffer inner_encoded;
        client_inner.Encode(inner_encoded);
        const auto answer = crypto::EncryptExchangeAnswer(inner_encoded.buf, temp_key, temp_iv);

        TLBuffer payload;
        payload.PutID(SetClientDhParams::kTypeId);
        payload.PutInt128(res.nonce);
        payload.PutInt128(res.server_nonce);
        payload.PutBytes(answer);
        send(MessageType::kFromClient, payload);
    }

    DhGenOk gen_ok;
    {
        TLBuffer b = recv();
        b.ConsumeID(DhGenOk::kTypeId);
        gen_ok.nonce = b.GetInt128();
        gen_ok.server_nonce = b.GetInt128();
        gen_ok.new_nonce_hash1 = b.GetInt128();
    }
    Check(gen_ok.new_nonce_hash1 == crypto::NonceHash1(new_nonce, result.auth_key),
          "handshake proof (new_nonce_hash1) checks out before disconnecting to test resume");

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    // The "store": a simple in-memory map the resolver looks up, populated
    // by on_success exactly like cmd/shuzagram_server/main.cpp populates
    // Postgres from the very same callback.
    std::mutex keys_mutex;
    std::map<std::array<std::uint8_t, 8>, ResolvedAuthKey> keys;

    RpcHandlerRegistry registry; // empty: only ping/rpc_error are needed here
    TcpHandshakeServer::AuthKeyResolver resolver =
        [&](const std::array<std::uint8_t, 8>& id) -> std::optional<ResolvedAuthKey> {
        std::lock_guard<std::mutex> lock(keys_mutex);
        const auto it = keys.find(id);
        if (it == keys.end()) return std::nullopt;
        return it->second;
    };
    TcpHandshakeServer server("127.0.0.1", /*port=*/0, server_private_key, &registry, resolver);
    const std::uint16_t port = server.Port();

    std::thread server_thread([&] {
        server.Run(
            [&](const ServerExchangeResult& result) {
                std::lock_guard<std::mutex> lock(keys_mutex);
                ResolvedAuthKey resolved;
                resolved.auth_key = result.auth_key;
                resolved.server_salt = result.server_salt;
                keys[crypto::AuthKeyId(result.auth_key)] = resolved;
            },
            [](const std::string& what) {
                std::printf("(server side connection ended: %s)\n", what.c_str());
            });
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    std::mt19937_64 rng(90210);

    // --- Connection 1: a normal full handshake, then disconnect ---
    HandshakeResult hs;
    {
        shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
        IntermediateCodec codec;
        codec.WriteHeader(socket.Writer());
        hs = RunHandshake(socket, codec, server_public_key, rng);
        // Give the server's on_success callback a moment to populate `keys`
        // before this socket goes away and the next connection races it.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        socket.Close();
    }

    // --- Connection 2: skip the handshake entirely, send an encrypted ping
    //     straight away -- exactly what a real client with a cached auth
    //     key does on reconnect. ---
    {
        shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
        IntermediateCodec codec;
        codec.WriteHeader(socket.Writer());

        const std::int64_t session_id = 24681357;
        const std::int64_t ping_msg_id =
            MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
        TLBuffer ping_payload;
        ping_payload.PutID(messages::Ping::kTypeId);
        ping_payload.PutLong(0xBEEF);
        const crypto::EncryptedMessage wire = crypto::EncryptMessage(hs.auth_key, hs.server_salt, session_id,
                                                                       ping_msg_id, 1, ping_payload.buf,
                                                                       crypto::Side::kClient);
        TLBuffer framed;
        wire.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);

        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        crypto::EncryptedMessage reply_wire;
        reply_wire.Decode(b);
        const crypto::EncryptedMessageData reply = crypto::DecryptMessage(hs.auth_key, reply_wire, crypto::Side::kClient);
        TLBuffer reply_body;
        reply_body.buf = reply.message_data;
        reply_body.ConsumeID(messages::Pong::kTypeId);
        const std::int64_t pong_msg_id = reply_body.Long();
        const std::int64_t pong_ping_id = reply_body.Long();
        Check(pong_msg_id == ping_msg_id,
              "reconnect with no handshake: server resumes the existing auth_key and replies to the real ping");
        Check(pong_ping_id == 0xBEEF, "reconnect with no handshake: pong.ping_id matches");

        socket.Close();
    }

    // --- Connection 3: an encrypted frame under an auth_key_id the
    //     resolver has never heard of -- must get a bare -404, not a hang
    //     or a silent drop. ---
    {
        shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
        IntermediateCodec codec;
        codec.WriteHeader(socket.Writer());

        crypto::AuthKeyBytes unknown_key{};
        unknown_key.fill(0x42); // never handshaked, never in `keys`
        const std::int64_t msg_id =
            MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
        TLBuffer ping_payload;
        ping_payload.PutID(messages::Ping::kTypeId);
        ping_payload.PutLong(1);
        const crypto::EncryptedMessage wire =
            crypto::EncryptMessage(unknown_key, /*salt=*/0, /*session_id=*/1, msg_id, 1, ping_payload.buf,
                                    crypto::Side::kClient);
        TLBuffer framed;
        wire.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);

        bool got_protocol_error = false;
        std::int32_t error_code = 0;
        try {
            codec.Read(socket.Reader());
        } catch (const ProtocolError& e) {
            got_protocol_error = true;
            error_code = e.code();
        }
        Check(got_protocol_error, "unknown auth_key_id on reconnect gets a transport protocol error, not a hang");
        Check(error_code == ProtocolError::kAuthKeyNotFound,
              "unknown auth_key_id on reconnect specifically gets -404 (auth key not found)");

        socket.Close();
    }

    server.Stop();
    server_thread.join();

    if (g_failures == 0) {
        std::printf("all net TCP key-resume tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d net TCP key-resume test(s) failed\n", g_failures);
    return 1;
}
