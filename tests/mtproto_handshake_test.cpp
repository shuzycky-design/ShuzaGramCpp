// End-to-end test of the server-side MTProto handshake
// (shuzagram::mtproto::ServerExchange::Run): a "fake client" thread plays
// the real client protocol -- including actually factoring the server's pq
// the way a real Telegram client would (Pollard/Brent decomposition, ported
// here as a test-only helper since the SERVER never needs to factor
// anything -- see NOTES/transport-handshake-plan.md) -- against the real
// server implementation running on another thread, connected by an
// in-memory duplex channel. Success means the two sides, running
// independent code paths, arrive at the identical auth_key and server_salt
// without either one trusting the other's math -- the actual proof this
// protocol implementation is correct, not merely internally consistent.

#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "shuzagram/mtproto/crypto/dh.hpp"
#include "shuzagram/mtproto/crypto/random.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"
#include "shuzagram/mtproto/messages/handshake.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/server_exchange.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace {

using namespace shuzagram::mtproto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (ok) {
        std::printf("ok: %s\n", what.c_str());
    } else {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// A blocking single-producer/single-consumer byte-frame queue, standing in
// for the TCP connection a real client/server would talk over.
class FrameChannel {
public:
    void Push(std::vector<std::uint8_t> frame) {
        std::lock_guard<std::mutex> lock(mu_);
        queue_.push_back(std::move(frame));
        cv_.notify_one();
    }

    std::vector<std::uint8_t> Pop() {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [&] { return !queue_.empty(); });
        std::vector<std::uint8_t> out = std::move(queue_.front());
        queue_.pop_front();
        return out;
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::vector<std::uint8_t>> queue_;
};

// --- Test-only pq factorization (the real client's job, never the server's) ---
//
// Faithful port of the algorithm in gotd/td's crypto/pq.go (a Pollard/Brent
// variant), simplified from arbitrary-precision big.Int to native
// uint64_t/__int128 arithmetic: MTProto's pq is always a product of two
// primes that together fit in 64 bits, so this is the same algorithm over
// the same value range, not a different one.
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
            // Pollard's rho iteration function x_{i+1} = x_i^2 + v (mod what).
            // The Go source computes this via binary long multiplication with
            // both operands set to a copy of x and the accumulator seeded at
            // v (`a.Set(x); b.Set(x); c.Set(v)` then the standard
            // double-and-add loop) -- i.e. x*x + v, not x*v as a more literal
            // reading of "a, b, c" might suggest.
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

std::vector<std::uint8_t> WrapUnencrypted(MessageType type, const TLBuffer& payload) {
    UnencryptedMessage msg;
    msg.message_id = MessageId::New(std::chrono::system_clock::now(), type).Raw();
    msg.message_data = payload.buf;
    TLBuffer out;
    msg.Encode(out);
    return out.buf;
}

TLBuffer UnwrapUnencrypted(const std::vector<std::uint8_t>& frame) {
    TLBuffer b;
    b.buf = frame;
    UnencryptedMessage msg;
    msg.Decode(b);
    TLBuffer payload;
    payload.buf = msg.message_data;
    return payload;
}

// The fake client's full run, mirroring exchange/client_flow.go but written
// directly against this test's own channel instead of a transport.Conn.
struct ClientResult {
    std::array<std::uint8_t, 256> auth_key{};
    std::int64_t server_salt = 0;
};

ClientResult RunFakeClient(FrameChannel& to_server, FrameChannel& from_server, const crypto::RsaPublicKey& server_key,
                            std::mt19937_64& rng) {
    using namespace messages;

    ReqPq req_msg;
    req_msg.type_id = kReqPqMultiRequestTypeId;
    req_msg.nonce = RandomInt128();
    {
        TLBuffer payload;
        payload.PutID(kReqPqMultiRequestTypeId);
        payload.PutInt128(req_msg.nonce);
        to_server.Push(WrapUnencrypted(MessageType::kFromClient, payload));
    }

    ResPq res;
    {
        TLBuffer b = UnwrapUnencrypted(from_server.Pop());
        b.ConsumeID(ResPq::kTypeId);
        res.nonce = b.GetInt128();
        res.server_nonce = b.GetInt128();
        res.pq = b.GetBytes();
        const auto count = b.VectorHeader();
        for (int i = 0; i < count; ++i) res.server_public_key_fingerprints.push_back(b.Long());
    }

    // Regression coverage: a real client (observed live, an Android
    // Telegram fork) plaintext-acknowledges ResPQ with a msgs_ack before
    // sending req_DH_params -- sometimes in the very same TCP segment. This
    // must not break the handshake (see NOTES/obfuscated2-transport-plan.md's
    // sibling note on the exact live failure this reproduces).
    {
        MsgsAck ack;
        ack.msg_ids = {1234};
        TLBuffer payload;
        ack.Encode(payload);
        to_server.Push(WrapUnencrypted(MessageType::kFromClient, payload));
    }

    const auto [p, q] = DecomposePq(BytesToU64(res.pq), rng);
    const auto p_bytes = U64ToMinimalBytes(p);
    const auto q_bytes = U64ToMinimalBytes(q);

    const Int256 new_nonce = RandomInt256();

    PqInnerData inner;
    inner.kind = PqInnerDataKind::kPlain;
    inner.pq = res.pq;
    inner.p = p_bytes;
    inner.q = q_bytes;
    inner.nonce = res.nonce;
    inner.server_nonce = res.server_nonce;
    inner.new_nonce = new_nonce;

    std::vector<std::uint8_t> encrypted_data;
    {
        TLBuffer inner_encoded;
        inner_encoded.PutID(PqInnerData::kPlainTypeId);
        inner_encoded.PutBytes(inner.pq);
        inner_encoded.PutBytes(inner.p);
        inner_encoded.PutBytes(inner.q);
        inner_encoded.PutInt128(inner.nonce);
        inner_encoded.PutInt128(inner.server_nonce);
        inner_encoded.PutInt256(inner.new_nonce);
        encrypted_data = crypto::RsaPad(inner_encoded.buf, server_key);
    }

    {
        ReqDhParams dh;
        dh.nonce = res.nonce;
        dh.server_nonce = res.server_nonce;
        dh.p = p_bytes;
        dh.q = q_bytes;
        dh.public_key_fingerprint = res.server_public_key_fingerprints.at(0);
        dh.encrypted_data = encrypted_data;
        TLBuffer payload;
        payload.PutID(ReqDhParams::kTypeId);
        payload.PutInt128(dh.nonce);
        payload.PutInt128(dh.server_nonce);
        payload.PutBytes(dh.p);
        payload.PutBytes(dh.q);
        payload.PutLong(dh.public_key_fingerprint);
        payload.PutBytes(dh.encrypted_data);
        to_server.Push(WrapUnencrypted(MessageType::kFromClient, payload));
    }

    ServerDhParamsOk ok;
    {
        TLBuffer b = UnwrapUnencrypted(from_server.Pop());
        b.ConsumeID(ServerDhParamsOk::kTypeId);
        ok.nonce = b.GetInt128();
        ok.server_nonce = b.GetInt128();
        ok.encrypted_answer = b.GetBytes();
    }

    // Second regression case for the same real-client quirk: msgs_ack
    // acknowledging server_DH_params_ok, before Set_client_DH_params.
    {
        MsgsAck ack;
        ack.msg_ids = {5678};
        TLBuffer payload;
        ack.Encode(payload);
        to_server.Push(WrapUnencrypted(MessageType::kFromClient, payload));
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

    ClientResult result;
    const auto auth_key_bytes =
        crypto::ModPowFixed(server_inner.g_a, client_secret_b, server_inner.dh_prime, 256);
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

        SetClientDhParams set;
        set.nonce = res.nonce;
        set.server_nonce = res.server_nonce;
        set.encrypted_data = answer;
        TLBuffer payload;
        payload.PutID(SetClientDhParams::kTypeId);
        payload.PutInt128(set.nonce);
        payload.PutInt128(set.server_nonce);
        payload.PutBytes(set.encrypted_data);
        to_server.Push(WrapUnencrypted(MessageType::kFromClient, payload));
    }

    DhGenOk gen_ok;
    {
        TLBuffer b = UnwrapUnencrypted(from_server.Pop());
        b.ConsumeID(DhGenOk::kTypeId);
        gen_ok.nonce = b.GetInt128();
        gen_ok.server_nonce = b.GetInt128();
        gen_ok.new_nonce_hash1 = b.GetInt128();
    }
    const Int128 expected_hash1 = crypto::NonceHash1(new_nonce, result.auth_key);
    Check(gen_ok.new_nonce_hash1 == expected_hash1,
          "client independently recomputes the same new_nonce_hash1 the server sent");

    return result;
}

} // namespace

int main() {
    const crypto::RsaPrivateKey server_private_key = crypto::RsaPrivateKey::Generate(2048);
    const crypto::RsaPublicKey server_public_key = server_private_key.PublicKey();

    FrameChannel to_server;
    FrameChannel from_server;

    ServerExchange exchange(server_private_key);
    ServerExchangeResult server_result;
    std::exception_ptr server_exception;

    std::thread server_thread([&] {
        try {
            server_result = exchange.Run([&] { return to_server.Pop(); },
                                          [&](const std::vector<std::uint8_t>& frame) { from_server.Push(frame); });
        } catch (...) {
            server_exception = std::current_exception();
        }
    });

    std::mt19937_64 rng(12345);
    const ClientResult client_result = RunFakeClient(to_server, from_server, server_public_key, rng);

    server_thread.join();
    if (server_exception) {
        try {
            std::rethrow_exception(server_exception);
        } catch (const std::exception& e) {
            Check(false, std::string("server exchange threw: ") + e.what());
        }
    } else {
        Check(true, "server exchange completed without throwing");
    }

    Check(client_result.auth_key == server_result.auth_key,
          "client and server independently derive the identical 256-byte auth_key");
    Check(client_result.server_salt == server_result.server_salt,
          "client and server independently derive the identical server_salt");

    if (g_failures == 0) {
        std::printf("all mtproto handshake tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto handshake test(s) failed\n", g_failures);
    return 1;
}
