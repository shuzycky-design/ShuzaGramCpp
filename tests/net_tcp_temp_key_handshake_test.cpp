// Real MTProto clients don't stop at one handshake per connection: they
// establish a permanent auth_key, then immediately run a SECOND,
// independent DH exchange over the SAME connection to establish a
// temporary (PFS) key (p_q_inner_data_temp_dc#56fddf88, carrying
// expires_in) -- acking the first handshake's dh_gen_ok with a plaintext
// msgs_ack in between, exactly like the msgs_ack pattern documented in
// NOTES/server-exchange-msgs-ack-plan.md -- and only THEN switch to
// encrypted traffic, under the TEMP key, not the permanent one. This is
// exactly the sequence a live capture from a real Android client
// (OwpenGram) showed: req_pq_multi -> msgs_ack -> req_DH_params ->
// msgs_ack -> Set_client_DH_params -> msgs_ack -> req_pq_multi (AGAIN).
//
// Before NOTES/temp-key-handshake-loop-plan.md's fix, tcp_handshake_server.cpp
// ran ServerExchange::Run() exactly once per connection and then
// unconditionally treated everything else as encrypted traffic under the
// FIRST (permanent) key -- so the second handshake's plaintext req_pq_multi
// got misread as an encrypted frame with auth_key_id == 0, failing with
// "unknown auth key id".

#include <atomic>
#include <chrono>
#include <cstdio>
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

// Runs one handshake round over `socket`/`codec` (already header-written,
// possibly already carrying an earlier handshake's traffic), optionally as
// a temporary/PFS key (p_q_inner_data_temp_dc, dc/expires_in set), and
// optionally acking every server reply with a plaintext msgs_ack the way
// the real client that motivated this test does.
HandshakeResult RunHandshake(shuzagram::net::TcpSocket& socket, IntermediateCodec& codec,
                              const crypto::RsaPublicKey& server_key, std::mt19937_64& rng, bool temp_key,
                              bool ack_every_reply) {
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
    auto ack = [&](std::int64_t acked_msg_id) {
        if (!ack_every_reply) return;
        MsgsAck msgs_ack;
        msgs_ack.msg_ids = {acked_msg_id};
        TLBuffer payload;
        msgs_ack.Encode(payload);
        send(MessageType::kFromClient, payload);
    };

    const Int128 nonce = RandomInt128();
    {
        TLBuffer payload;
        payload.PutID(kReqPqMultiRequestTypeId);
        payload.PutInt128(nonce);
        send(MessageType::kFromClient, payload);
    }

    ResPq res;
    std::int64_t res_pq_msg_id = 0;
    {
        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(b);
        res_pq_msg_id = msg.message_id;
        b.buf = msg.message_data;
        b.ConsumeID(ResPq::kTypeId);
        res.nonce = b.GetInt128();
        res.server_nonce = b.GetInt128();
        res.pq = b.GetBytes();
        const auto count = b.VectorHeader();
        for (int i = 0; i < count; ++i) res.server_public_key_fingerprints.push_back(b.Long());
    }
    ack(res_pq_msg_id);

    const auto [p, q] = DecomposePq(BytesToU64(res.pq), rng);
    const auto p_bytes = U64ToMinimalBytes(p);
    const auto q_bytes = U64ToMinimalBytes(q);
    const Int256 new_nonce = RandomInt256();

    std::vector<std::uint8_t> encrypted_data;
    {
        TLBuffer inner_encoded;
        inner_encoded.PutID(temp_key ? PqInnerData::kTempDcTypeId : PqInnerData::kPlainTypeId);
        inner_encoded.PutBytes(res.pq);
        inner_encoded.PutBytes(p_bytes);
        inner_encoded.PutBytes(q_bytes);
        inner_encoded.PutInt128(res.nonce);
        inner_encoded.PutInt128(res.server_nonce);
        inner_encoded.PutInt256(new_nonce);
        if (temp_key) {
            inner_encoded.PutInt32(1);    // dc
            inner_encoded.PutInt32(3600); // expires_in (seconds)
        }
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
    std::int64_t dh_params_ok_msg_id = 0;
    {
        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(b);
        dh_params_ok_msg_id = msg.message_id;
        b.buf = msg.message_data;
        b.ConsumeID(ServerDhParamsOk::kTypeId);
        ok.nonce = b.GetInt128();
        ok.server_nonce = b.GetInt128();
        ok.encrypted_answer = b.GetBytes();
    }
    ack(dh_params_ok_msg_id);

    std::vector<std::uint8_t> temp_aes_key, temp_aes_iv;
    crypto::TempAesKeys(new_nonce, res.server_nonce, temp_aes_key, temp_aes_iv);

    ServerDhInnerData server_inner;
    {
        const auto decrypted = crypto::DecryptExchangeAnswer(ok.encrypted_answer, temp_aes_key, temp_aes_iv);
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
        const auto answer = crypto::EncryptExchangeAnswer(inner_encoded.buf, temp_aes_key, temp_aes_iv);

        TLBuffer payload;
        payload.PutID(SetClientDhParams::kTypeId);
        payload.PutInt128(res.nonce);
        payload.PutInt128(res.server_nonce);
        payload.PutBytes(answer);
        send(MessageType::kFromClient, payload);
    }

    DhGenOk gen_ok;
    std::int64_t dh_gen_ok_msg_id = 0;
    {
        const auto frame = codec.Read(socket.Reader());
        TLBuffer b;
        b.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(b);
        dh_gen_ok_msg_id = msg.message_id;
        b.buf = msg.message_data;
        b.ConsumeID(DhGenOk::kTypeId);
        gen_ok.nonce = b.GetInt128();
        gen_ok.server_nonce = b.GetInt128();
        gen_ok.new_nonce_hash1 = b.GetInt128();
    }
    Check(gen_ok.new_nonce_hash1 == crypto::NonceHash1(new_nonce, result.auth_key),
          std::string("handshake proof (new_nonce_hash1) checks out (") + (temp_key ? "temp" : "permanent") +
              " key)");
    ack(dh_gen_ok_msg_id);

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    RpcHandlerRegistry registry; // empty: only ping/rpc_error are needed here
    std::atomic<int> handshakes_completed{0};
    TcpHandshakeServer server("127.0.0.1", /*port=*/0, server_private_key, &registry);
    const std::uint16_t port = server.Port();

    std::thread server_thread([&] {
        server.Run([&](const ServerExchangeResult&) { ++handshakes_completed; },
                    [](const std::string& what) {
                        std::printf("(server side connection ended: %s)\n", what.c_str());
                    });
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    shuzagram::net::TcpSocket socket = shuzagram::net::TcpSocket::Connect("127.0.0.1", port);
    IntermediateCodec codec;
    codec.WriteHeader(socket.Writer());

    std::mt19937_64 rng(24601);

    // Round 1: permanent key, acking every server reply -- exactly what the
    // real client that motivated this test does.
    RunHandshake(socket, codec, server_public_key, rng, /*temp_key=*/false, /*ack_every_reply=*/true);

    // Round 2, SAME connection, no reconnect: temporary/PFS key. Before the
    // fix, the server would misread this round's req_pq_multi as an
    // encrypted frame under round 1's key and fail with "unknown auth key
    // id" instead of ever reaching here.
    const HandshakeResult temp_hs =
        RunHandshake(socket, codec, server_public_key, rng, /*temp_key=*/true, /*ack_every_reply=*/true);

    // Now real encrypted traffic under the TEMP key, matching what a real
    // client actually encrypts its ongoing traffic with after PFS setup.
    const std::int64_t session_id = 13371337;
    const std::int64_t ping_msg_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    TLBuffer ping_payload;
    ping_payload.PutID(messages::Ping::kTypeId);
    ping_payload.PutLong(0xFEED);
    const crypto::EncryptedMessage wire = crypto::EncryptMessage(temp_hs.auth_key, temp_hs.server_salt, session_id,
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
    const crypto::EncryptedMessageData reply =
        crypto::DecryptMessage(temp_hs.auth_key, reply_wire, crypto::Side::kClient);
    TLBuffer reply_body;
    reply_body.buf = reply.message_data;
    reply_body.ConsumeID(messages::Pong::kTypeId);
    const std::int64_t pong_msg_id = reply_body.Long();
    const std::int64_t pong_ping_id = reply_body.Long();
    Check(pong_msg_id == ping_msg_id, "encrypted ping under the TEMP key (not the permanent one) gets a real pong");
    Check(pong_ping_id == 0xFEED, "pong.ping_id matches under the temp key");
    // By the time the server has processed and replied to this encrypted
    // ping, both on_success calls (round 1 and round 2) must already have
    // happened on the server's own thread -- strictly earlier in program
    // order than the loop iteration that read this ping at all.
    Check(handshakes_completed == 2, "both handshake rounds over the same connection completed (auth_key + temp key)");

    socket.Close();
    server.Stop();
    server_thread.join();

    if (g_failures == 0) {
        std::printf("all net TCP temp-key handshake tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d net TCP temp-key handshake test(s) failed\n", g_failures);
    return 1;
}
