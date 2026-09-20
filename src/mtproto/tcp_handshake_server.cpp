#include "shuzagram/mtproto/tcp_handshake_server.hpp"

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <thread>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/session.hpp"
#include "shuzagram/mtproto/transport/detect_transport.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace shuzagram::mtproto {
namespace {

// The real client that motivated NOTES/server-exchange-msgs-ack-plan.md
// acks every server-sent handshake message with a plaintext msgs_ack --
// including dh_gen_ok, the server's LAST plaintext reply, which arrives
// after this loop has already switched to treating every frame as an
// encrypted session message. A stray plaintext msgs_ack here would
// otherwise be misread as an encrypted frame with auth_key_id == 0 (its
// 8-byte zero auth_key_id envelope prefix), which never matches the real
// derived key -- "unknown auth key id". A real auth_key_id is a
// cryptographic hash and is never actually zero, so treating an
// all-zero-prefixed frame as a stray plaintext ack (rather than a
// malformed encrypted one) is safe.
bool IsPlaintextMsgsAck(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < 8) return false;
    for (int i = 0; i < 8; ++i) {
        if (frame[i] != 0) return false;
    }
    try {
        TLBuffer buf;
        buf.buf = frame;
        UnencryptedMessage msg;
        msg.Decode(buf);
        TLBuffer peek;
        peek.buf = msg.message_data;
        return peek.PeekID() == messages::MsgsAck::kTypeId;
    } catch (...) {
        return false;
    }
}

// Temporary field diagnostic (SHUZAGRAM_DEBUG_TRANSPORT=1): dumps every raw
// byte a connection actually sent, regardless of where parsing failed, to
// stderr. Real clients in the wild have already turned up two undocumented
// quirks (obfuscated2, and a plaintext msgs_ack before req_DH_params) that
// no synthetic test predicted -- this exists to see the NEXT one directly
// instead of guessing from exception messages alone.
bool DebugTransportEnabled() {
    const char* v = std::getenv("SHUZAGRAM_DEBUG_TRANSPORT");
    return v && *v && std::string(v) != "0";
}

void LogRawBytes(const std::vector<std::uint8_t>& bytes, const char* what) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    static const char kHex[] = "0123456789abcdef";
    for (const auto b : bytes) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0xF]);
    }
    std::fprintf(stderr, "[transport debug] %s (%zu bytes): %s\n", what, bytes.size(), hex.c_str());
}

} // namespace

TcpHandshakeServer::TcpHandshakeServer(const std::string& bind_address, std::uint16_t port, crypto::RsaPrivateKey key,
                                        const RpcHandlerRegistry* rpc_registry)
    : listener_(bind_address, port), key_(std::move(key)), rpc_registry_(rpc_registry) {}

void TcpHandshakeServer::Run(const SuccessHandler& on_success, const FailureHandler& on_failure) {
    // Polls with a short timeout rather than blocking in Accept()
    // indefinitely, so Stop() (which just flips stopping_) is noticed
    // promptly and reliably -- see AcceptWithTimeout's doc comment for why
    // this loop doesn't just close the listening fd from another thread
    // instead.
    constexpr auto kPollInterval = std::chrono::milliseconds(200);
    while (!stopping_.load()) {
        std::optional<net::TcpSocket> socket = listener_.AcceptWithTimeout(kPollInterval);
        if (!socket) continue;

        // One detached thread per connection: simple and adequate for this
        // round's goal (prove the wiring works), not a production-grade
        // connection-handling model. See NOTES/tcp-wiring-plan.md.
        std::thread([this, socket = std::move(*socket), on_success, on_failure]() mutable {
            const bool debug = DebugTransportEnabled();
            auto raw_log = std::make_shared<std::vector<std::uint8_t>>();
            try {
                auto raw_reader = socket.Reader();
                auto writer = socket.Writer();
                mtproto::transport::ReadExact reader = raw_reader;
                if (debug) {
                    reader = [raw_reader, raw_log](std::uint8_t* dst, std::size_t len) {
                        raw_reader(dst, len);
                        raw_log->insert(raw_log->end(), dst, dst + len);
                    };
                }
                // DetectTransport (not the bare DetectCodec this project
                // used before this round) transparently also accepts
                // obfuscated2 -- what a real client sends by default -- see
                // NOTES/obfuscated2-transport-plan.md. No MTProxy secret:
                // this server is a direct DC, not a proxy hop.
                transport::DetectedTransport detected = transport::DetectTransport(reader, writer);
                ServerExchange exchange(key_);
                const ServerExchangeResult result = exchange.Run(
                    [&] { return detected.codec->Read(detected.read); },
                    [&](const std::vector<std::uint8_t>& frame) { detected.codec->Write(detected.write, frame); });
                if (on_success) on_success(result);

                if (!rpc_registry_) return; // old behavior: close right after the handshake

                // Continue serving this same connection: read encrypted
                // frames, dispatch them through MtprotoSession, write back
                // whatever replies it produces, until the connection ends.
                // session_id starts at 0 -- MtprotoSession adopts the
                // client's real one from the first decrypted message (see
                // its own header comment).
                MtprotoSession session(result.auth_key, /*session_id=*/0, result.server_salt, crypto::Side::kServer,
                                       rpc_registry_);
                for (;;) {
                    std::vector<std::uint8_t> frame;
                    do {
                        frame = detected.codec->Read(detected.read);
                    } while (IsPlaintextMsgsAck(frame));
                    TLBuffer frame_buf;
                    frame_buf.buf = frame;
                    crypto::EncryptedMessage encrypted;
                    encrypted.Decode(frame_buf);

                    const auto replies = session.HandleEncrypted(encrypted);
                    for (const auto& reply : replies) {
                        TLBuffer out;
                        reply.Encode(out);
                        detected.codec->Write(detected.write, out.buf);
                    }
                }
            } catch (const std::exception& e) {
                if (debug) LogRawBytes(*raw_log, e.what());
                if (on_failure) on_failure(e.what());
            } catch (...) {
                if (debug) LogRawBytes(*raw_log, "unknown error");
                if (on_failure) on_failure("unknown error");
            }
        }).detach();
    }
}

void TcpHandshakeServer::Stop() {
    // Just the flag: Run()'s poll loop checks it at least once per
    // kPollInterval, so this returns almost immediately without needing to
    // touch the listening socket while Run() might still be polling on it
    // concurrently (see AcceptWithTimeout's doc comment for why that would
    // be unsafe). The listener itself closes when this object is
    // destroyed.
    stopping_.store(true);
}

} // namespace shuzagram::mtproto
