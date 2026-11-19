> **Moved.** This library now lives in [aoughwl/std](https://github.com/aoughwl/std/tree/main/tls) (directory `tls/`), with its full history. This repository is kept as a redirect; new work happens in `aoughwl/std`.

# tls

**TLS/SSL for the [aoughwl](https://aoughwl.github.io) net stack**, over OpenSSL 3
— client *and* server. Wraps a connected `net.Socket` into a `TlsSocket`; no
framework runtime, no exceptions (status-based `TlsStatus`), caller-owned buffers.

```nim
import net, tls

# client: resolve + connect + handshake in one call
var ctx = newTlsClientContext(verify = true)
var c = connectTls(ctx, "example.com", 443)
discard c.sendAll("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
echo c.protocolVersion(), " / ", c.cipherName()   # TLSv1.3 / TLS_AES_256_GCM_SHA384
```

## Contents
{: .no_toc }

- [Motivation](#motivation)
- [What it does](#what-it-does)
- [Layout](#layout)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Testing](#testing)
- [Requirements](#requirements)
- [License](#license)

## Motivation

| Want | `tls` |
|---|---|
| TLS 1.3 that just works, both roles | client (SNI, hostname verification, system trust store, ALPN, cipher/version control) and server (PEM cert chain + key, ALPN selection) |
| Drive it from a poll loop | the handshake is resumable — blocking *or* non-blocking, surfacing `tlsWantRead`/`tlsWantWrite` |
| No exception model | every call returns a status/count; nothing is thrown |
| Reusable across the stack | `serve` (HTTPS), `ws` (`wss://`), and HTTP/2 ALPN all sit on this one layer |

## What it does

| Capability | Detail |
|---|---|
| Client context | `newTlsClientContext`, SNI + `SSL_set1_host` verification, `loadVerifyLocations`, cipher list / suites, min/max version |
| Server context | `newTlsServerContext(cert, key)`, `setAlpnServer` (real ALPN negotiation via `alpn_select_cb`) |
| Handshake | `wrapClient` / `wrapServer` / `connectTls`; resumable via `handshake` |
| I/O | `tlsReadInto` / `tlsWriteFrom`, plus `recv` / `readAll` / `send` / `sendAll` |
| Introspection | `protocolVersion`, `cipherName`, `negotiatedAlpn`, `verifyOk` / `verifyResultCode` |

## Layout

```
tls.nim         # TlsContext / TlsSocket, OpenSSL 3 FFI, handshake, I/O, ALPN
tests/
  ttls_loopback.nim     # our client ⇄ our server over a generated cert (TLS 1.3)
  ttls_client_live.nim  # real HTTPS GET to example.com, cert verified
  ttls_compile.nim      # offline surface smoke
```

## Design notes

- **Opaque handles as `pointer`.** `SSL_CTX` / `SSL` are held as nil-checked
  pointers; the FFI binds `libssl.so.3` / `libcrypto.so.3` by symbol (no headers).
- **ALPN, both directions.** `setAlpnProtocols` advertises (client); `setAlpnServer`
  registers the server selection callback so a server actually negotiates `h2`.
- **Non-blocking ready.** `SSL_do_handshake` is surfaced through `TlsStatus`, so the
  same `TlsSocket` works under a blocking or an event-loop caller.

## Limitations

- One `TlsContext` per process for server ALPN (the select callback reads a
  process-global preference list).
- No session-ticket tuning / OCSP stapling / client-cert *requirement* yet
  (client certs can be *offered*).
- BoringSSL-style browser fingerprinting is out of scope — that lives in
  [`requests`](https://github.com/aoughwl/requests) via curl-impersonate.

## Testing

```
nimony c -r --path:. --path:../aoughwl-net --path:../aoughwl-tcp tests/ttls_loopback.nim
```

`ttls_loopback` negotiates TLS 1.3 / AES-256-GCM between our own client and server
over a throwaway self-signed cert and round-trips a payload; `ttls_client_live`
verifies a real certificate against example.com.

## Requirements

- Nimony, OpenSSL 3 (`libssl.so.3`, `libcrypto.so.3`).
- [`net`](https://github.com/aoughwl/net) (for `Socket`) and
  [`tcp`](https://github.com/aoughwl/tcp).

## License

MIT.
