// Tests for messages/invoke.hpp's UnwrapInvokeWrappers, exercised through
// the full MtprotoSession/crypto round trip (not just called directly) so
// this proves real clients' actual wire shape -- invokeWithLayer(layer,
// initConnection(..., query)) and nested variants -- reaches the same
// ping/registry dispatch a bare call does. Same "real crypto round trip,
// not just unit-call the function" discipline as mtproto_session_test.cpp.

#include <chrono>
#include <cstdio>
#include <string>

#include "shuzagram/mtproto/messages/invoke.hpp"
#include "shuzagram/mtproto/messages/system.hpp"
#include "shuzagram/mtproto/session.hpp"
#include "shuzagram/mtproto/unencrypted_message.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
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

EncryptedMessage ClientEncrypt(const AuthKeyBytes& key, std::int64_t salt, std::int64_t session_id,
                                const std::vector<std::uint8_t>& payload) {
    const std::int64_t msg_id = MessageId::New(std::chrono::system_clock::now(), MessageType::kFromClient).Raw();
    return EncryptMessage(key, salt, session_id, msg_id, /*seq_no=*/1, payload, Side::kClient);
}

std::vector<std::uint8_t> EncodePing(std::int64_t ping_id) {
    TLBuffer b;
    b.PutID(messages::Ping::kTypeId);
    b.PutLong(ping_id);
    return b.buf;
}

// Wraps `inner`'s already-encoded bytes in invokeWithLayer#da9b0d0d.
std::vector<std::uint8_t> WrapInvokeWithLayer(int layer, const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInvokeWithLayerTypeId);
    b.PutInt32(layer);
    b.Put(inner);
    return b.buf;
}

std::vector<std::uint8_t> WrapInvokeWithoutUpdates(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInvokeWithoutUpdatesTypeId);
    b.Put(inner);
    return b.buf;
}

// Wraps `inner` in initConnection#c1cd5ea9 with flags=0 (no proxy, no
// params) and plausible-looking metadata fields.
std::vector<std::uint8_t> WrapInitConnection(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInitConnectionTypeId);
    b.PutUint32(0); // flags
    b.PutInt32(12345); // api_id
    b.PutBytes(std::vector<std::uint8_t>{'t', 'e', 's', 't'}); // device_model
    b.PutBytes(std::vector<std::uint8_t>{'1', '.', '0'});      // system_version
    b.PutBytes(std::vector<std::uint8_t>{'1', '.', '0'});      // app_version
    b.PutBytes({});                                            // system_lang_code
    b.PutBytes({});                                            // lang_pack
    b.PutBytes(std::vector<std::uint8_t>{'e', 'n'});           // lang_code
    b.Put(inner);
    return b.buf;
}

// Same shape as WrapInitConnection but with the proxy flag (bit 0) set and
// a real inputClientProxy#75588b3f value following, then `inner`.
std::vector<std::uint8_t> WrapInitConnectionWithProxy(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInitConnectionTypeId);
    b.PutUint32(1u << 0); // flags: proxy present
    b.PutInt32(12345);
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutID(0x75588b3f); // inputClientProxy
    b.PutBytes(std::vector<std::uint8_t>{'1', '.', '2', '.', '3', '.', '4'}); // address
    b.PutInt32(443);                                                          // port
    b.Put(inner);
    return b.buf;
}

// A real JSONValue payload exercising every branch of SkipJsonValue:
// jsonObject{"a": jsonArray[jsonNumber, jsonBool, jsonNull], "b": jsonString}.
std::vector<std::uint8_t> EncodeSampleJsonValue() {
    TLBuffer b;
    b.PutID(0x99c1d49d); // jsonObject
    b.PutVectorHeader(2);
    {
        b.PutID(0xc0de1bd9); // jsonObjectValue
        b.PutBytes(std::vector<std::uint8_t>{'a'});
        b.PutID(0xf7444763); // jsonArray
        b.PutVectorHeader(3);
        b.PutID(0x2be0dfa4); // jsonNumber
        b.Put(std::vector<std::uint8_t>(8, 0));  // double bit pattern, value irrelevant
        b.PutID(0xc7345e6a); // jsonBool
        b.PutID(0x997275b5); // boolTrue
        b.PutID(0x3f6d7b68); // jsonNull
    }
    {
        b.PutID(0xc0de1bd9); // jsonObjectValue
        b.PutBytes(std::vector<std::uint8_t>{'b'});
        b.PutID(0xb71e767a); // jsonString
        b.PutBytes(std::vector<std::uint8_t>{'h', 'i'});
    }
    return b.buf;
}

// Same shape as WrapInitConnection but with the params flag (bit 1) set
// and a real, non-trivial JSONValue following, then `inner` -- exactly
// what every real client this project has been tested against actually
// sends on every single call.
std::vector<std::uint8_t> WrapInitConnectionWithParams(const std::vector<std::uint8_t>& inner) {
    TLBuffer b;
    b.PutID(messages::kInitConnectionTypeId);
    b.PutUint32(1u << 1); // flags: params present
    b.PutInt32(12345);
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.PutBytes({});
    b.Put(EncodeSampleJsonValue());
    b.Put(inner);
    return b.buf;
}

EncryptedMessageData Roundtrip(MtprotoSession& server, const AuthKeyBytes& key, std::int64_t salt,
                                std::int64_t session_id, const std::vector<std::uint8_t>& payload) {
    const auto replies = server.HandleEncrypted(ClientEncrypt(key, salt, session_id, payload));
    Check(replies.size() == 1, "produces exactly one reply");
    if (replies.empty()) throw std::runtime_error("no reply");
    return DecryptMessage(key, replies[0], Side::kClient);
}

void TestBarePingStillWorks() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, EncodePing(1));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    Check(true, "a bare (unwrapped) ping is unaffected by adding unwrap support");
}

void TestInvokeWithLayerWrappedPing() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInvokeWithLayer(177, EncodePing(2)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long(); // msg_id
    Check(b.Long() == 2, "invokeWithLayer(177, ping) unwraps and dispatches to the real ping");
}

void TestInitConnectionWrappedPing() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInitConnection(EncodePing(3)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 3, "initConnection(..., ping) unwraps and dispatches to the real ping");
}

void TestDeeplyNestedWrappers() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    // invokeWithLayer(177, initConnection(..., invokeWithoutUpdates(ping)))
    const auto nested = WrapInvokeWithLayer(177, WrapInitConnection(WrapInvokeWithoutUpdates(EncodePing(4))));
    const auto reply = Roundtrip(server, key, 222, 111, nested);
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 4, "three levels of nested invoke wrappers all unwrap correctly");
}

void TestWrappedCallReachesRegisteredHandler() {
    const AuthKeyBytes key = RandomAuthKey();
    constexpr std::uint32_t kDemoMethodId = 0x12345678;
    RpcHandlerRegistry registry;
    registry.Register(kDemoMethodId, [](std::uint32_t, TLBuffer&, const RpcContext&) -> std::vector<std::uint8_t> {
        messages::Pong fake_response;
        fake_response.msg_id = 0;
        fake_response.ping_id = 999;
        TLBuffer out;
        fake_response.Encode(out);
        return out.buf;
    });
    MtprotoSession server(key, 111, 222, Side::kServer, &registry);

    TLBuffer call;
    call.PutID(kDemoMethodId);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInvokeWithLayer(177, call.buf));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::RpcResult::kTypeId);
    b.Long(); // req_msg_id
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 999, "a wrapped call reaches a registered business-method handler, same as a bare call would");
}

void TestInitConnectionWithProxyIsSkippedCorrectly() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInitConnectionWithProxy(EncodePing(5)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 5, "initConnection with a real proxy value skips it correctly and reaches the real ping");
}

// Found live: every real client this project has been tested against
// (OwpenGram) sets initConnection's params flag on literally every call.
// Before SkipJsonValue existed, this made UnwrapInvokeWrappers throw for
// every single real call, so nothing past the handshake was ever actually
// reachable by a real client -- see NOTES/init-connection-params-plan.md.
void TestInitConnectionWithParamsIsSkippedCorrectly() {
    const AuthKeyBytes key = RandomAuthKey();
    MtprotoSession server(key, 111, 222, Side::kServer);
    const auto reply = Roundtrip(server, key, 222, 111, WrapInitConnectionWithParams(EncodePing(6)));
    TLBuffer b;
    b.buf = reply.message_data;
    b.ConsumeID(messages::Pong::kTypeId);
    b.Long();
    Check(b.Long() == 6,
          "initConnection with a real (object/array/number/bool/null/string) JSON params value skips it "
          "correctly and reaches the real ping");
}

} // namespace

int main() {
    TestBarePingStillWorks();
    TestInvokeWithLayerWrappedPing();
    TestInitConnectionWrappedPing();
    TestDeeplyNestedWrappers();
    TestWrappedCallReachesRegisteredHandler();
    TestInitConnectionWithProxyIsSkippedCorrectly();
    TestInitConnectionWithParamsIsSkippedCorrectly();
    if (g_failures == 0) {
        std::printf("all mtproto invoke-wrapper tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto invoke-wrapper test(s) failed\n", g_failures);
    return 1;
}
