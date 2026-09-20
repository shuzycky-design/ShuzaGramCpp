// Tests for MtprotoSession/RpcHandlerRegistry: the RPC dispatch
// infrastructure built on top of the already-verified message cipher. Runs
// two independent sessions (one playing "client", one "server") over the
// same auth_key/session_id/salt, exactly the way the handshake tests run
// two independent protocol roles against each other -- proving the
// dispatch logic is correct, not just self-consistent with itself.

#include <chrono>
#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/session.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (ok) {
        std::printf("ok: %s\n", what.c_str());
    } else {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

AuthKeyBytes RandomAuthKey() {
    AuthKeyBytes key{};
    const auto r = SystemRandomBytes(256);
    std::copy(r.begin(), r.end(), key.begin());
    return key;
}

// Builds one client-encrypted EncryptedMessage carrying `payload` as the
// sole top-level content (not wrapped in a container).
EncryptedMessage ClientEncrypt(const AuthKeyBytes& key, std::int64_t salt, std::int64_t session_id,
                                const std::vector<std::uint8_t>& payload, std::int64_t* out_msg_id = nullptr) {
    const std::int64_t msg_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    if (out_msg_id) *out_msg_id = msg_id;
    return EncryptMessage(key, salt, session_id, msg_id, /*seq_no=*/1, payload, Side::kClient);
}

std::vector<std::uint8_t> EncodePing(std::int64_t ping_id) {
    TLBuffer b;
    b.PutID(messages::Ping::kTypeId);
    b.PutLong(ping_id);
    return b.buf;
}

std::vector<std::uint8_t> EncodePingDelayDisconnect(std::int64_t ping_id, int disconnect_delay) {
    TLBuffer b;
    b.PutID(messages::PingDelayDisconnect::kTypeId);
    b.PutLong(ping_id);
    b.PutInt32(disconnect_delay);
    return b.buf;
}

std::vector<std::uint8_t> EncodeUnknownCall(std::uint32_t fake_constructor_id) {
    TLBuffer b;
    b.PutID(fake_constructor_id);
    b.PutInt32(42); // some fake field, contents don't matter for this test
    return b.buf;
}

void TestPingPong() {
    const AuthKeyBytes key = RandomAuthKey();
    const std::int64_t session_id = 111;
    const std::int64_t salt = 222;

    MtprotoSession server(key, session_id, salt, Side::kServer);

    std::int64_t ping_msg_id = 0;
    const EncryptedMessage request = ClientEncrypt(key, salt, session_id, EncodePing(0xABCD), &ping_msg_id);

    const auto replies = server.HandleEncrypted(request);
    Check(replies.size() == 1, "ping produces exactly one reply");
    if (replies.empty()) return;

    const EncryptedMessageData reply_data = DecryptMessage(key, replies[0], Side::kClient);
    TLBuffer b;
    b.buf = reply_data.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    const std::int64_t pong_msg_id = b.Long();
    const std::int64_t pong_ping_id = b.Long();

    Check(pong_msg_id == ping_msg_id, "pong.msg_id echoes the original ping message's own msg_id");
    Check(pong_ping_id == 0xABCD, "pong.ping_id matches the ping's ping_id");
    Check(reply_data.session_id == session_id, "reply carries the correct session_id");
}

// ping_delay_disconnect#f3427b8c -- the keepalive variant a real Android
// client (OwpenGram) turned out to send exclusively, instead of plain
// ping. Found live: it fell through to METHOD_NOT_FOUND, which looked to
// the client like the connection was unhealthy ("infinite loading").
void TestPingDelayDisconnectGetsPong() {
    const AuthKeyBytes key = RandomAuthKey();
    const std::int64_t session_id = 111;
    const std::int64_t salt = 222;

    MtprotoSession server(key, session_id, salt, Side::kServer);

    std::int64_t ping_msg_id = 0;
    const EncryptedMessage request =
        ClientEncrypt(key, salt, session_id, EncodePingDelayDisconnect(0x1234, 75), &ping_msg_id);

    const auto replies = server.HandleEncrypted(request);
    Check(replies.size() == 1, "ping_delay_disconnect produces exactly one reply");
    if (replies.empty()) return;

    const EncryptedMessageData reply_data = DecryptMessage(key, replies[0], Side::kClient);
    TLBuffer b;
    b.buf = reply_data.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    const std::int64_t pong_msg_id = b.Long();
    const std::int64_t pong_ping_id = b.Long();

    Check(pong_msg_id == ping_msg_id, "ping_delay_disconnect: pong.msg_id echoes the request's own msg_id");
    Check(pong_ping_id == 0x1234, "ping_delay_disconnect: pong.ping_id matches, same as plain ping's reply shape");
}

void TestUnknownRpcGetsMethodNotFound() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);

    constexpr std::uint32_t kFakeMethodId = 0xDEADBEEF;
    std::int64_t req_msg_id = 0;
    const EncryptedMessage request = ClientEncrypt(key, 222, 111, EncodeUnknownCall(kFakeMethodId), &req_msg_id);

    const auto replies = server.HandleEncrypted(request);
    Check(replies.size() == 1, "an unimplemented RPC call still produces exactly one reply");
    if (replies.empty()) return;

    const EncryptedMessageData reply_data = DecryptMessage(key, replies[0], Side::kClient);
    TLBuffer b;
    b.buf = reply_data.message_data;
    b.ConsumeID(messages::RpcResult::kTypeId);
    const std::int64_t got_req_msg_id = b.Long();
    Check(got_req_msg_id == req_msg_id, "rpc_result.req_msg_id matches the original call's msg_id");

    b.ConsumeID(messages::RpcError::kTypeId);
    const int error_code = b.Int32();
    const auto message_bytes = b.GetBytes();
    const std::string message(message_bytes.begin(), message_bytes.end());
    Check(error_code == 400, "unimplemented method gets error_code 400");
    Check(message.find("METHOD_NOT_FOUND") != std::string::npos, "error message names the constructor as not found");
}

void TestRegisteredHandlerIsUsed() {
    const AuthKeyBytes key = RandomAuthKey();
    constexpr std::uint32_t kDemoMethodId = 0x12345678;

    RpcHandlerRegistry registry;
    registry.Register(kDemoMethodId, [](std::uint32_t, TLBuffer& body, const RpcContext&) -> std::vector<std::uint8_t> {
        const std::int32_t echoed_field = body.Int32();
        // A trivial demo "response" object: reuse Pong's shape purely as a
        // convenient pre-existing encodable type, msg_id=0 since it's not
        // actually a pong semantically -- this handler only exists to prove
        // the registry extension point is wired up, not to model a real
        // method.
        messages::Pong fake_response;
        fake_response.msg_id = 0;
        fake_response.ping_id = echoed_field;
        TLBuffer out;
        fake_response.Encode(out);
        return out.buf;
    });

    MtprotoSession server(key, 111, 222, Side::kServer, &registry);
    std::vector<std::uint8_t> call;
    {
        TLBuffer b;
        b.PutID(kDemoMethodId);
        b.PutInt32(777);
        call = b.buf;
    }
    const EncryptedMessage request = ClientEncrypt(key, 222, 111, call);
    const auto replies = server.HandleEncrypted(request);
    Check(replies.size() == 1, "a registered handler's response still produces exactly one reply");
    if (replies.empty()) return;

    const EncryptedMessageData reply_data = DecryptMessage(key, replies[0], Side::kClient);
    TLBuffer b;
    b.buf = reply_data.message_data;
    b.ConsumeID(messages::RpcResult::kTypeId);
    b.Long(); // req_msg_id, not checked here
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long(); // msg_id field of the fake response, unused
    const std::int64_t echoed = b.Long();
    Check(echoed == 777, "the registered handler's own response reaches the client, wrapped in rpc_result");
}

void TestMsgsAckProducesNoReply() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);

    messages::MsgsAck ack;
    ack.msg_ids = {1, 2, 3};
    TLBuffer b;
    ack.Encode(b);
    const EncryptedMessage request = ClientEncrypt(key, 222, 111, b.buf);

    const auto replies = server.HandleEncrypted(request);
    Check(replies.empty(), "msgs_ack produces no reply");
}

void TestMsgContainerDispatchesEachInnerMessage() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);

    messages::MsgContainer container;
    const std::int64_t base_id =
        MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    messages::ContainerMessage m1;
    m1.msg_id = base_id;
    m1.seqno = 1;
    m1.body = EncodePing(0x1111);
    messages::ContainerMessage m2;
    m2.msg_id = base_id + 4; // must stay a valid client-yield id and strictly increasing
    m2.seqno = 3;
    m2.body = EncodePing(0x2222);
    container.messages = {m1, m2};

    TLBuffer container_encoded;
    container.Encode(container_encoded);

    const std::int64_t outer_msg_id =
        MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    const EncryptedMessage request =
        EncryptMessage(key, 222, 111, outer_msg_id, /*seq_no=*/1, container_encoded.buf, Side::kClient);

    const auto replies = server.HandleEncrypted(request);
    Check(replies.size() == 2, "a container with two pings produces two replies");
    if (replies.size() != 2) return;

    for (std::size_t i = 0; i < replies.size(); ++i) {
        const EncryptedMessageData reply_data = DecryptMessage(key, replies[i], Side::kClient);
        TLBuffer b;
        b.buf = reply_data.message_data;
        b.ConsumeID(messages::Pong::kTypeId);
        const std::int64_t pong_msg_id = b.Long();
        const std::int64_t pong_ping_id = b.Long();
        Check(pong_msg_id == (i == 0 ? m1.msg_id : m2.msg_id),
              "reply " + std::to_string(i) + " echoes its own container message's msg_id, not the outer one");
        Check(pong_ping_id == (i == 0 ? 0x1111 : 0x2222), "reply " + std::to_string(i) + " matches its own ping_id");
    }
}

void TestReplayProtectionRejectsNonIncreasingMsgId() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);

    const std::int64_t msg_id =
        MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    const EncryptedMessage first =
        EncryptMessage(key, 222, 111, msg_id, 1, EncodePing(1), Side::kClient);
    server.HandleEncrypted(first);

    // Re-send the exact same message (same msg_id) -- a classic replay.
    bool rejected = false;
    try {
        server.HandleEncrypted(first);
    } catch (const std::exception&) {
        rejected = true;
    }
    Check(rejected, "replaying the same msg_id a second time is rejected");
}

} // namespace

int main() {
    TestPingPong();
    TestPingDelayDisconnectGetsPong();
    TestUnknownRpcGetsMethodNotFound();
    TestRegisteredHandlerIsUsed();
    TestMsgsAckProducesNoReply();
    TestMsgContainerDispatchesEachInnerMessage();
    TestReplayProtectionRejectsNonIncreasingMsgId();

    if (g_failures == 0) {
        std::printf("all mtproto session tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto session test(s) failed\n", g_failures);
    return 1;
}
