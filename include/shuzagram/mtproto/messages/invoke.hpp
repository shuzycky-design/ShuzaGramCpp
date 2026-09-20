#pragma once

#include <cstdint>

#include "shuzagram/mtproto/tl_buffer.hpp"

// The "invoke wrapper" TL constructors real clients use to wrap almost
// every actual RPC call: invokeWithLayer#da9b0d0d layer:int query:!X = X,
// initConnection#c1cd5ea9 ... query:!X = X, invokeWithoutUpdates#bf9459b7
// query:!X = X, invokeAfterMsg#cb9f372d msg_id:long query:!X = X. None of
// them are business methods -- they carry a few metadata fields, then the
// REAL call's own encoding (constructor id + fields) follows immediately,
// with no length prefix (query:!X is "the rest of this object", not a TL
// bytes field).
//
// Before this was ported, every RPC handler this project registered
// (auth.sendCode, auth.signIn, ...) could only be reached by a test client
// that called it completely bare -- which is NOT what any real MTProto
// client does: TDesktop/Android/iOS/WebK all wrap at least their first
// call (usually every call) in invokeWithLayer(layer, initConnection(...,
// query)). Without unwrapping these, a real client's very first request
// would hit MtprotoSession::DispatchOne's registry lookup on
// InvokeWithLayerRequestTypeID, find nothing, and get METHOD_NOT_FOUND --
// so nothing built in every earlier round was actually reachable by a
// genuine client. See NOTES/invoke-wrappers-plan.md.
namespace shuzagram::mtproto::messages {

inline constexpr std::uint32_t kInvokeWithLayerTypeId = 0xda9b0d0d;
inline constexpr std::uint32_t kInvokeWithoutUpdatesTypeId = 0xbf9459b7;
inline constexpr std::uint32_t kInvokeAfterMsgTypeId = 0xcb9f372d;
inline constexpr std::uint32_t kInitConnectionTypeId = 0xc1cd5ea9;

// JSONValue (mt.tl): jsonNull#3f6d7b68 = JSONValue; jsonBool#c7345e6a
// value:Bool = JSONValue; jsonNumber#2be0dfa4 value:double = JSONValue;
// jsonString#b71e767a value:string = JSONValue; jsonArray#f7444763
// value:Vector<JSONValue> = JSONValue; jsonObject#99c1d49d
// value:Vector<JSONObjectValue> = JSONValue; jsonObjectValue#c0de1bd9
// key:string value:JSONValue = JSONObjectValue.
//
// Every current real client (this was found live: OwpenGram sets this on
// literally every call) sets initConnection's params flag to attach an
// arbitrary JSON blob (tz_offset, perf_cat, ...) this server has no use
// for -- but the buffer still has to be advanced past it correctly for
// whatever comes after (the real RPC call) to parse at all. Recursively
// walks and discards a JSONValue without needing to interpret it.
inline void SkipJsonValue(TLBuffer& b) {
    constexpr std::uint32_t kJsonNullTypeId = 0x3f6d7b68;
    constexpr std::uint32_t kJsonBoolTypeId = 0xc7345e6a;
    constexpr std::uint32_t kJsonNumberTypeId = 0x2be0dfa4;
    constexpr std::uint32_t kJsonStringTypeId = 0xb71e767a;
    constexpr std::uint32_t kJsonArrayTypeId = 0xf7444763;
    constexpr std::uint32_t kJsonObjectTypeId = 0x99c1d49d;
    constexpr std::uint32_t kJsonObjectValueTypeId = 0xc0de1bd9;

    const std::uint32_t id = b.PeekID();
    b.ConsumeID(id);
    switch (id) {
        case kJsonNullTypeId:
            break;
        case kJsonBoolTypeId: {
            const std::uint32_t bool_id = b.PeekID();
            b.ConsumeID(bool_id); // boolTrue/boolFalse, no further fields
            break;
        }
        case kJsonNumberTypeId:
            (void)b.Uint64(); // double, bit pattern doesn't matter to discard it
            break;
        case kJsonStringTypeId:
            (void)b.GetBytes();
            break;
        case kJsonArrayTypeId: {
            const auto count = b.VectorHeader();
            for (int i = 0; i < count; ++i) SkipJsonValue(b);
            break;
        }
        case kJsonObjectTypeId: {
            const auto count = b.VectorHeader();
            for (int i = 0; i < count; ++i) {
                b.ConsumeID(kJsonObjectValueTypeId);
                (void)b.GetBytes(); // key
                SkipJsonValue(b);   // value
            }
            break;
        }
        default:
            throw UnexpectedIdError(id);
    }
}

// Repeatedly strips any of the four wrapper constructors above off the
// FRONT of `b` (a client can nest them, e.g.
// invokeWithLayer(initConnection(invokeWithoutUpdates(realCall)))),
// leaving exactly the real call's own id+fields in `b` for the ordinary
// dispatch path to handle as before. A buffer that starts with none of
// these ids is left untouched (the common case once unwrapped, or a
// legacy/bare call with no wrapper at all).
//
// initConnection's device/app metadata (api_id, device_model, ...) is
// decoded and discarded, not yet persisted into store::AuthKeyClientInfo
// -- that wiring is a separate future round.
inline void UnwrapInvokeWrappers(TLBuffer& b) {
    for (;;) {
        const std::uint32_t id = b.PeekID();
        if (id == kInvokeWithLayerTypeId) {
            b.ConsumeID(id);
            (void)b.Int32(); // layer
            continue;
        }
        if (id == kInvokeWithoutUpdatesTypeId) {
            b.ConsumeID(id);
            continue;
        }
        if (id == kInvokeAfterMsgTypeId) {
            b.ConsumeID(id);
            (void)b.Long(); // msg_id
            continue;
        }
        if (id == kInitConnectionTypeId) {
            b.ConsumeID(id);
            const std::uint32_t flags = b.Uint32();
            (void)b.Int32();     // api_id
            (void)b.GetBytes();  // device_model
            (void)b.GetBytes();  // system_version
            (void)b.GetBytes();  // app_version
            (void)b.GetBytes();  // system_lang_code
            (void)b.GetBytes();  // lang_pack
            (void)b.GetBytes();  // lang_code
            // proxy:flags.0?InputClientProxy -- inputClientProxy#75588b3f
            // address:string port:int = InputClientProxy (its only
            // constructor, not a union like JSONValue).
            if (flags & (1u << 0)) {
                b.ConsumeID(0x75588b3f);
                (void)b.GetBytes(); // address
                (void)b.Int32();    // port
            }
            // params:flags.1?JSONValue -- found live: every real client
            // this project has been tested against sets this
            // unconditionally (tz_offset/perf_cat/... telemetry blob),
            // so leaving it unhandled meant EVERY real call from a real
            // client failed with a 500 INTERNAL error before even
            // reaching the actual RPC method -- see
            // NOTES/init-connection-params-plan.md.
            if (flags & (1u << 1)) SkipJsonValue(b);
            continue;
        }
        return;
    }
}

} // namespace shuzagram::mtproto::messages
