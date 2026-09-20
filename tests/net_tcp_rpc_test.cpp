// Capstone for the RPC-dispatch round: a real TCP connection that survives
// past the handshake. The fake client completes the handshake exactly like
// net_tcp_handshake_test.cpp, then -- over the SAME socket and codec, no
// reconnect -- sends one real encrypted `ping` and one real encrypted
// unimplemented-method call, and checks it gets back a correctly-shaped
// `pong` and `rpc_result(rpc_error)` respectively. Proves
// TcpHandshakeServer's optional post-handshake MtprotoSession continuation
// actually works over a real socket, not just in the in-process
// mtproto_session_test.cpp unit tests.

#include <chrono>
#include <condition_variable>
#include <cstdio>
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

// Runs the handshake over `socket`/`codec` (already header-written) and
// leaves the connection open for further use afterward.
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
          "handshake proof (new_nonce_hash1) checks out before continuing on the same connection");

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    RpcHandlerRegistry registry; // intentionally empty: proves ping/rpc_error work with zero business methods
    TcpHandshakeServer server("127.0.0.1", /*port=*/0, server_private_key, &registry);
    const std::uint16_t port = server.Port();

    std::mutex mu;
    std::condition_variable cv;
    bool handshake_done = false;
    ServerExchangeResult server_handshake_result;

    std::thread server_thread([&] {
        server.Run(
            [&](const ServerExchangeResult& result) {
                std::lock_guard<std::mutex> lock(mu);
                server_handshake_result = result;
                handshake_done = true;
                cv.notify_all();
            },
            [](const std::string& what) {
                // A connection close after the client is done is expected
                // and not a failure -- just log it for visibility.
                std::printf("(server side connection ended: %s)\n", what.c_str());
            });
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
    IntermediateCodec codec;
    codec.WriteHeader(socket.Writer());

    std::mt19937_64 rng(31337);
    const HandshakeResult hs = RunHandshake(socket, codec, server_public_key, rng);

    {
        std::unique_lock<std::mutex> lock(mu);
        Check(cv.wait_for(lock, std::chrono::seconds(10), [&] { return handshake_done; }),
              "server-side handshake completed within the timeout");
    }
    Check(hs.auth_key == server_handshake_result.auth_key, "client/server auth_key still matches before RPC phase");

    // The real Android client that motivated NOTES/server-exchange-msgs-ack-plan.md
    // acks EVERY server handshake message, including dh_gen_ok -- the
    // server's LAST plaintext reply, sent after this connection has
    // already switched from ServerExchange to MtprotoSession. Without the
    // corresponding skip in tcp_handshake_server.cpp's post-handshake read
    // loop, this stray plaintext frame's all-zero auth_key_id envelope
    // prefix gets misread as an encrypted frame with auth_key_id == 0,
    // failing with "unknown auth key id" on the very next real message.
    {
        messages::MsgsAck ack;
        ack.msg_ids = {hs.server_salt}; // arbitrary; server discards the ack outright
        TLBuffer ack_payload;
        ack.Encode(ack_payload);
        UnencryptedMessage ack_msg;
        ack_msg.message_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
        ack_msg.message_data = ack_payload.buf;
        TLBuffer framed;
        ack_msg.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);
    }

    // --- Now the actual capstone: real encrypted traffic over the same connection ---
    const std::int64_t session_id = 555444333;
    auto send_encrypted = [&](const std::vector<std::uint8_t>& payload, std::int64_t msg_id, std::int32_t seq_no) {
        const crypto::EncryptedMessage wire =
            crypto::EncryptMessage(hs.auth_key, hs.server_salt, session_id, msg_id, seq_no, payload, crypto::Side::kClient);
        TLBuffer framed;
        wire.Encode(framed);
        codec.Write(socket.Writer(), framed.buf);
    };
    auto recv_encrypted = [&]() -> crypto::EncryptedMessageData {
        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        crypto::EncryptedMessage wire;
        wire.Decode(b);
        // Client's own role is kClient, so it expects the opposite
        // (kServer) to be the actual sender -- decrypt_as names MY role,
        // not the sender's.
        return crypto::DecryptMessage(hs.auth_key, wire, crypto::Side::kClient);
    };

    {
        const std::int64_t ping_msg_id =
            MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
        TLBuffer ping_payload;
        ping_payload.PutID(messages::Ping::kTypeId);
        ping_payload.PutLong(0xC0FFEE);
        send_encrypted(ping_payload.buf, ping_msg_id, 1);

        const crypto::EncryptedMessageData reply = recv_encrypted();
        TLBuffer b;
        b.buf = reply.message_data;
        b.ConsumeID(messages::Pong::kTypeId);
        const std::int64_t pong_msg_id = b.Long();
        const std::int64_t pong_ping_id = b.Long();
        Check(pong_msg_id == ping_msg_id, "real encrypted ping over TCP: pong.msg_id matches");
        Check(pong_ping_id == 0xC0FFEE, "real encrypted ping over TCP: pong.ping_id matches");
        Check(reply.session_id == session_id, "reply carries the session_id this client established");
    }

    {
        constexpr std::uint32_t kFakeMethodId = 0x600DF00D;
        const std::int64_t call_msg_id =
            MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
        TLBuffer call_payload;
        call_payload.PutID(kFakeMethodId);
        send_encrypted(call_payload.buf, call_msg_id, 3);

        const crypto::EncryptedMessageData reply = recv_encrypted();
        TLBuffer b;
        b.buf = reply.message_data;
        b.ConsumeID(messages::RpcResult::kTypeId);
        const std::int64_t req_msg_id = b.Long();
        b.ConsumeID(messages::RpcError::kTypeId);
        const int error_code = b.Int32();
        Check(req_msg_id == call_msg_id, "real encrypted unimplemented-method call over TCP: rpc_result echoes msg_id");
        Check(error_code == 400, "real encrypted unimplemented-method call over TCP: rpc_error code is 400");
    }

    socket.Close();
    server.Stop();
    server_thread.join();

    if (g_failures == 0) {
        std::printf("all net TCP RPC tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d net TCP RPC test(s) failed\n", g_failures);
    return 1;
}
