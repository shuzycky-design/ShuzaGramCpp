#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/rpc_dispatch.hpp"
#include "shuzagram/mtproto/server_exchange.hpp"
#include "shuzagram/net/tcp_listener.hpp"

// Wires TcpListener + transport::DetectCodec + ServerExchange (+ optionally
// MtprotoSession) together: the first piece of this project that actually
// listens on a real TCP port. One thread per accepted connection (a real
// epoll/async-IO event loop is a deliberately separate, later piece -- see
// NOTES/tcp-wiring-plan.md).
//
// Deliberately independent of the store:: layer: what happens with a
// completed handshake (persisting the auth_key, and everything after) is
// the caller's job via the result callback, not this class's -- so it can
// be exercised in tests without a live Postgres, and so cmd/shuzagram_server
// is the only place that wires the two together.
namespace shuzagram::mtproto {

// A previously-established auth key, resolved out-of-band (typically from
// store::IAuthKeyStore) so a reconnecting client that skips the handshake
// entirely -- see AuthKeyResolver below -- can resume being served instead
// of having its connection dropped.
struct ResolvedAuthKey {
    crypto::AuthKeyBytes auth_key{};
    std::int64_t server_salt = 0;
};

class TcpHandshakeServer {
public:
    // Looks up an existing auth key by id, or nullopt if it's unknown/no
    // longer valid (expired, revoked, ...). Deliberately a callback rather
    // than a direct store::IAuthKeyStore dependency, for the same reason
    // on_success/on_failure are callbacks: this class stays exercisable in
    // tests without a live Postgres, and cmd/shuzagram_server is the only
    // place that wires the two together. Whatever validity rules apply
    // (existence, expiry, migration-artifact rejection, ...) are entirely
    // the resolver's responsibility.
    using AuthKeyResolver = std::function<std::optional<ResolvedAuthKey>(const std::array<std::uint8_t, 8>&)>;

    // rpc_registry == nullptr (the default): a connection is closed right
    // after its handshake completes, exactly as in the first TCP-wiring
    // round -- what every existing caller/test still gets unchanged.
    // rpc_registry != nullptr: after on_success runs, the SAME connection
    // continues to be served by an MtprotoSession built from that registry
    // (still answering ping/msgs_ack/unknown-method-error even if the
    // registry itself has no business handlers registered), until the
    // connection closes or a session-level error occurs. The pointee must
    // outlive this server.
    //
    // auth_key_resolver (only consulted when rpc_registry is also set): a
    // real client that already holds an auth key for this server (from an
    // earlier connection) skips the handshake on reconnect and sends an
    // encrypted frame straight away -- ServerExchange can't handle that
    // itself (see UnexpectedEncryptedFrameError's header comment for why
    // this must not just be treated as a handshake failure). Left unset,
    // such a connection is simply dropped, same as before this parameter
    // existed.
    TcpHandshakeServer(const std::string& bind_address, std::uint16_t port, crypto::RsaPrivateKey key,
                        const RpcHandlerRegistry* rpc_registry = nullptr, AuthKeyResolver auth_key_resolver = {});

    [[nodiscard]] std::uint16_t Port() const { return listener_.Port(); }

    // Called (from a connection's own worker thread -- may be called
    // concurrently from several threads for several connections at once,
    // callers must be thread-safe) once a connection's handshake succeeds.
    using SuccessHandler = std::function<void(const ServerExchangeResult&)>;
    // Called on any failure (bad transport, failed handshake, I/O error, or
    // -- when rpc_registry is set -- an ordinary connection close/error
    // while serving that connection's session). Purely informational; the
    // connection is closed either way.
    using FailureHandler = std::function<void(const std::string& what)>;

    // Blocks, accepting connections and spawning one detached worker thread
    // per connection, until Stop() is called from another thread.
    void Run(const SuccessHandler& on_success, const FailureHandler& on_failure = {});

    // Requests that Run()'s accept loop exit; returns immediately (does not
    // wait for Run() to actually return -- join whatever thread is running
    // it for that). Safe to call from a different thread than the one
    // running Run(). Run() notices within one poll interval (currently
    // 200ms), not instantly -- see tcp_handshake_server.cpp.
    void Stop();

private:
    net::TcpListener listener_;
    crypto::RsaPrivateKey key_;
    const RpcHandlerRegistry* rpc_registry_;
    AuthKeyResolver auth_key_resolver_;
    std::atomic<bool> stopping_{false};
};

} // namespace shuzagram::mtproto
