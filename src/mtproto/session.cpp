#include "shuzagram/mtproto/session.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include "shuzagram/mtproto/messages/invoke.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace shuzagram::mtproto {
namespace {

// Same SHUZAGRAM_DEBUG_TRANSPORT toggle tcp_handshake_server.cpp uses --
// once a connection reaches this class, its transport/handshake layer is
// already trusted, but a real client's very first RPC calls (what method,
// does the registry actually have it) have turned out to matter just as
// much: OwpenGram completed both handshakes cleanly and then just sat
// there, connection eventually closed by the peer, with zero visibility
// into what it actually asked for. See NOTES/rpc-visibility-plan.md.
bool DebugTransportEnabled() {
    const char* v = std::getenv("SHUZAGRAM_DEBUG_TRANSPORT");
    return v && *v && std::string(v) != "0";
}

} // namespace

MtprotoSession::MtprotoSession(crypto::AuthKeyBytes auth_key, std::int64_t session_id, std::int64_t server_salt,
                                crypto::Side my_side, const RpcHandlerRegistry* registry)
    : auth_key_(auth_key), session_id_(session_id), server_salt_(server_salt), my_side_(my_side), registry_(registry) {}

std::int64_t MtprotoSession::NextSeqNo(bool content_related) {
    // Official formula (core.telegram.org/mtproto/description#message-sequence-number-msg-seqno):
    // a content-related message gets 2N+1 (then N increments); a
    // non-content one gets 2N using the current N without incrementing.
    if (content_related) {
        const std::int64_t seq = 2 * content_seq_counter_ + 1;
        ++content_seq_counter_;
        return seq;
    }
    return 2 * content_seq_counter_;
}

crypto::EncryptedMessage MtprotoSession::EncryptOutgoing(const std::vector<std::uint8_t>& body) {
    const std::int64_t msg_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kServerResponse).Raw();
    const std::int32_t seq_no = static_cast<std::int32_t>(NextSeqNo(/*content_related=*/true));
    return crypto::EncryptMessage(auth_key_, server_salt_, session_id_, msg_id, seq_no, body, my_side_);
}

std::vector<std::uint8_t> MtprotoSession::DispatchOne(std::int64_t msg_id, const std::vector<std::uint8_t>& body) {
    using namespace messages;

    TLBuffer b;
    b.buf = body;

    // Strips invokeWithLayer/initConnection/invokeWithoutUpdates/
    // invokeAfterMsg off the front, if present -- see messages/invoke.hpp
    // for why this has to happen before anything else: real clients wrap
    // almost every call in at least one of these, and without unwrapping,
    // ping/msgs_ack/registry lookup below would all be matching against
    // the WRAPPER's id instead of the real call's.
    try {
        UnwrapInvokeWrappers(b);
    } catch (const std::exception& e) {
        RpcError error;
        error.error_code = 500;
        error.error_message = std::string("INTERNAL ") + e.what();
        TLBuffer error_out;
        error.Encode(error_out);
        RpcResult wrapped;
        wrapped.req_msg_id = msg_id;
        wrapped.result = std::move(error_out.buf);
        TLBuffer out;
        wrapped.Encode(out);
        return out.buf;
    }

    const std::uint32_t id = b.PeekID();
    const bool debug = DebugTransportEnabled();
    if (debug) std::fprintf(stderr, "[rpc debug] incoming method=0x%08x\n", id);

    if (id == Ping::kTypeId) {
        b.ConsumeID(id);
        Ping ping;
        ping.DecodeBare(b);
        Pong pong;
        pong.msg_id = msg_id; // the incoming message's own id, per spec -- not a fresh one
        pong.ping_id = ping.ping_id;
        TLBuffer out;
        pong.Encode(out);
        return out.buf;
    }
    if (id == PingDelayDisconnect::kTypeId) {
        // Same Pong response as plain Ping -- see PingDelayDisconnect's own
        // doc comment for why disconnect_delay itself is ignored. Real
        // clients (this gap was found live, via a real Android client that
        // uses this variant exclusively for its keepalive) send THIS, not
        // plain Ping -- answering it with METHOD_NOT_FOUND instead of a
        // real Pong looks to the client like the connection is unhealthy.
        b.ConsumeID(id);
        PingDelayDisconnect ping;
        ping.DecodeBare(b);
        Pong pong;
        pong.msg_id = msg_id;
        pong.ping_id = ping.ping_id;
        TLBuffer out;
        pong.Encode(out);
        return out.buf;
    }
    if (id == MsgsAck::kTypeId) {
        // Nothing to do this round: we don't track our own outbound
        // delivery-confirmation state yet (see NOTES/rpc-dispatch-plan.md).
        return {};
    }

    // Anything else is treated as an RPC call (this project implements no
    // actual business methods -- see NOTES/rpc-dispatch-plan.md).
    std::vector<std::uint8_t> result;
    if (registry_) {
        if (const RpcHandler* handler = registry_->Find(id)) {
            b.ConsumeID(id);
            const RpcContext ctx{crypto::AuthKeyId(auth_key_), session_id_};
            // Captured BEFORE the handler runs and possibly throws: a
            // handler decode failure needs the exact plaintext bytes to
            // diagnose (this is already-decrypted RPC content, not
            // wire-encrypted -- SHUZAGRAM_DEBUG_TRANSPORT already implies
            // willingness to see raw protocol bytes in this log).
            const std::vector<std::uint8_t> body_snapshot(b.buf);
            try {
                result = (*handler)(id, b, ctx);
            } catch (const std::exception& e) {
                if (debug) {
                    std::string hex;
                    hex.reserve(body_snapshot.size() * 2);
                    static const char kHex[] = "0123456789abcdef";
                    for (const auto byte : body_snapshot) {
                        hex.push_back(kHex[byte >> 4]);
                        hex.push_back(kHex[byte & 0xF]);
                    }
                    std::fprintf(stderr, "[rpc debug] method=0x%08x handler threw: %s; body (%zu bytes): %s\n", id,
                                  e.what(), body_snapshot.size(), hex.c_str());
                }
                throw;
            }
        }
    }
    if (debug) {
        if (result.empty()) {
            std::fprintf(stderr, "[rpc debug] method=0x%08x -> METHOD_NOT_FOUND (400)\n", id);
        } else {
            TLBuffer peek;
            peek.buf = result;
            const std::uint32_t result_id = peek.PeekID();
            if (result_id == RpcError::kTypeId) {
                peek.ConsumeID(result_id);
                const int error_code = peek.Int32();
                const std::vector<std::uint8_t> msg_bytes = peek.GetBytes();
                const std::string error_message(msg_bytes.begin(), msg_bytes.end());
                std::fprintf(stderr, "[rpc debug] method=0x%08x -> rpc_error code=%d message=%s\n", id, error_code,
                              error_message.c_str());
            } else {
                std::fprintf(stderr, "[rpc debug] method=0x%08x -> handled (result id=0x%08x)\n", id, result_id);
            }
        }
    }
    if (result.empty()) {
        RpcError error;
        error.error_code = 400;
        char hex[11];
        std::snprintf(hex, sizeof(hex), "0x%08x", id);
        error.error_message = std::string("METHOD_NOT_FOUND ") + hex;
        TLBuffer out;
        error.Encode(out);
        result = out.buf;
    }

    RpcResult wrapped;
    wrapped.req_msg_id = msg_id;
    wrapped.result = std::move(result);
    TLBuffer out;
    wrapped.Encode(out);
    return out.buf;
}

std::vector<crypto::EncryptedMessage> MtprotoSession::HandleEncrypted(const crypto::EncryptedMessage& incoming) {
    const crypto::EncryptedMessageData data =
        crypto::DecryptMessage(auth_key_, incoming, my_side_);
    // session_id is the client's to set; the server just mirrors whatever
    // it used back on every outgoing message within this session, rather
    // than needing to know it up front at construction time.
    session_id_ = data.session_id;

    if (data.message_id <= last_seen_msg_id_) {
        // A real implementation also has to tell "duplicate retransmit of
        // an already-answered message" apart from "a genuine replay
        // attack" and often needs to resend the previous answer rather
        // than just rejecting -- deliberately simplified here, see
        // NOTES/rpc-dispatch-plan.md.
        throw std::runtime_error("msg_id is not strictly increasing (possible replay)");
    }
    last_seen_msg_id_ = data.message_id;

    std::vector<InnerMessage> inner;
    {
        TLBuffer b;
        b.buf = data.message_data;
        const std::uint32_t id = b.PeekID();
        if (id == messages::MsgContainer::kTypeId) {
            b.ConsumeID(id);
            messages::MsgContainer container;
            container.DecodeBare(b);
            inner.reserve(container.messages.size());
            for (auto& m : container.messages) inner.push_back({m.msg_id, std::move(m.body)});
        } else {
            inner.push_back({data.message_id, data.message_data});
        }
    }

    std::vector<crypto::EncryptedMessage> replies;
    for (const auto& m : inner) {
        std::vector<std::uint8_t> response = DispatchOne(m.msg_id, m.body);
        if (!response.empty()) replies.push_back(EncryptOutgoing(response));
    }
    return replies;
}

} // namespace shuzagram::mtproto
