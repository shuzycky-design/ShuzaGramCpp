#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for the "core system" messages every MTProto session needs
// regardless of which business RPC methods exist -- containers, ping/pong,
// acks, and the rpc_result/rpc_error envelope. Field order and type ids
// copied directly from gotd/td's generated mt/tl_*_gen.go, same as
// messages/handshake.hpp. See NOTES/rpc-dispatch-plan.md for what this
// deliberately does NOT include (the actual business API surface, and
// GzipPacked compression on Message::body/RpcResult::result -- neither
// side of this port ever produces or expects gzip-wrapped content, so both
// are read/written as raw bytes).
namespace shuzagram::mtproto::messages {

// message#5bb8e511 msg_id:long seqno:int bytes:int body:bytes = Message;
//
// NOT a top-level TL object in its own right on the wire (no leading type
// id byte) -- it only ever appears bare, as an element of msg_container's
// vector. body's length is exactly `bytes`, with no TL bytes-style padding
// (the wrapped object is itself already a whole number of 4-byte words).
struct ContainerMessage {
    std::int64_t msg_id = 0;
    std::int32_t seqno = 0;
    std::vector<std::uint8_t> body;

    void EncodeBare(TLBuffer& b) const {
        b.PutLong(msg_id);
        b.PutInt32(seqno);
        b.PutInt32(static_cast<std::int32_t>(body.size()));
        b.Put(body.data(), body.size());
    }
    void DecodeBare(TLBuffer& b) {
        msg_id = b.Long();
        seqno = b.Int32();
        const auto len = static_cast<std::size_t>(b.Int32());
        body.resize(len);
        b.ConsumeN(body.data(), len);
    }
};

// msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
//
// Note the bare vector (no 0x1cb5c415 marker, unlike an ordinary
// `vector<long>`): just a raw int32 count followed by each ContainerMessage
// bare-encoded in sequence.
struct MsgContainer {
    static constexpr std::uint32_t kTypeId = 0x73f1f8dc;

    std::vector<ContainerMessage> messages;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt32(static_cast<std::int32_t>(messages.size()));
        for (const auto& m : messages) m.EncodeBare(b);
    }
    // Assumes ConsumeID(kTypeId) was already done by the caller (matching
    // how every other Decode() in this project works: the caller peeks the
    // id to decide which type to construct before decoding it).
    void DecodeBare(TLBuffer& b) {
        const auto count = static_cast<std::size_t>(b.Int32());
        messages.resize(count);
        for (auto& m : messages) m.DecodeBare(b);
    }
};

// ping#7abe77ec ping_id:long = Pong;
struct Ping {
    static constexpr std::uint32_t kTypeId = 0x7abe77ec;
    std::int64_t ping_id = 0;

    void DecodeBare(TLBuffer& b) { ping_id = b.Long(); }
};

// ping_delay_disconnect#f3427b8c ping_id:long disconnect_delay:int = Pong;
// The variant real clients actually send for their keepalive: same Pong
// response as plain ping, plus a hint ("disconnect me if you don't hear
// from me again within disconnect_delay seconds") this server doesn't act
// on -- answering with a normal Pong is enough to satisfy the client's own
// liveness check.
struct PingDelayDisconnect {
    static constexpr std::uint32_t kTypeId = 0xf3427b8c;
    std::int64_t ping_id = 0;
    int disconnect_delay = 0;

    void DecodeBare(TLBuffer& b) {
        ping_id = b.Long();
        disconnect_delay = b.Int32();
    }
};

// pong#347773c5 msg_id:long ping_id:long = Pong;
struct Pong {
    static constexpr std::uint32_t kTypeId = 0x347773c5;
    std::int64_t msg_id = 0;
    std::int64_t ping_id = 0;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutLong(msg_id);
        b.PutLong(ping_id);
    }
};

// msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;
struct MsgsAck {
    static constexpr std::uint32_t kTypeId = 0x62d6b459;
    std::vector<std::int64_t> msg_ids;

    void DecodeBare(TLBuffer& b) {
        const auto count = b.VectorHeader();
        msg_ids.resize(static_cast<std::size_t>(count));
        for (auto& id : msg_ids) id = b.Long();
    }
    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutVectorHeader(msg_ids.size());
        for (const auto id : msg_ids) b.PutLong(id);
    }
};

// rpc_error#2144ca19 error_code:int error_message:string = RpcError;
struct RpcError {
    static constexpr std::uint32_t kTypeId = 0x2144ca19;
    int error_code = 0;
    std::string error_message;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt32(error_code);
        const std::vector<std::uint8_t> msg_bytes(error_message.begin(), error_message.end());
        b.PutBytes(msg_bytes);
    }
};

// rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult;
//
// `result` is whatever the wrapped object's own encoding is (already
// carrying its own type id) -- not a TL bytes field, so no length prefix
// of its own here; the caller supplies it pre-encoded.
struct RpcResult {
    static constexpr std::uint32_t kTypeId = 0xf35c6d01;
    std::int64_t req_msg_id = 0;
    std::vector<std::uint8_t> result; // pre-encoded inner object

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutLong(req_msg_id);
        b.Put(result.data(), result.size());
    }
};

} // namespace shuzagram::mtproto::messages
