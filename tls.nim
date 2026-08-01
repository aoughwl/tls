## net/tls.nim — TLS/SSL for `net`, over OpenSSL 3 (libssl.so.3 / libcrypto.so.3).
##
## A `TlsSocket` wraps a connected blocking `Socket` and drives the handshake
## and record layer through OpenSSL. Both roles are supported: a client context
## (`newTlsClientContext`, SNI + certificate verification + ALPN + hostname
## checking) and a server context (`newTlsServerContext`, certificate + key).
##
## Design in the aoughwl idiom: status-based returns (`TlsStatus`), no
## exceptions, caller-owned buffers, opaque handles as `pointer` (nil-checked).
## The context holds the long-lived `SSL_CTX`; each connection gets its own
## `SSL`. Works with blocking or non-blocking sockets — on a non-blocking socket
## the handshake / read / write surface `tlsWantRead` / `tlsWantWrite` so a
## caller can drive it from a poll loop.

import net
import tcp
import tlsconfig
export tlsconfig

const
  sslLib = "libssl.so.3"
  cryptoLib = "libcrypto.so.3"

type
  TlsMode* = enum
    tlsClient, tlsServer

  TlsContext* = object
    ## A long-lived TLS configuration (wraps `SSL_CTX`). Reuse across many
    ## connections. `handle` is nil when construction failed. `stateId` is a
    ## 1-based index into the per-context server-side state registry (SNI certs
    ## + ALPN); 0 means "no state allocated yet" (the default), so raw
    ## `TlsContext(...)` construction stays valid.
    handle*: nil pointer
    mode*: TlsMode
    stateId*: int

  TlsSocket* = object
    ## One TLS connection over a `Socket` (wraps `SSL`). `ssl` is nil when
    ## invalid.
    socket*: Socket
    ssl*: nil pointer
    handshakeDone*: bool

  TlsSession* = object
    ## A captured, resumable TLS session (wraps a refcounted `SSL_SESSION`).
    ## Obtain one with `getSession` after a handshake, stash it, and pass it to
    ## a later `wrapClient` / `connectTls` to attempt TLS 1.3 resumption. Free it
    ## with `freeSession` when done. `handle` is nil when invalid.
    handle*: nil pointer

  TlsStatus* = enum
    tlsOk,          ## operation completed
    tlsWantRead,    ## non-blocking: retry after the socket is readable
    tlsWantWrite,   ## non-blocking: retry after the socket is writable
    tlsClosed,      ## peer sent close_notify / clean EOF
    tlsError        ## fatal protocol or transport error

# ---------------------------------------------------------------------------
# OpenSSL FFI.  Opaque structs are `pointer`; we only ever pass them around.
# ---------------------------------------------------------------------------

const
  SSL_FILETYPE_PEM = cint(1)
  SSL_VERIFY_NONE = cint(0)
  SSL_VERIFY_PEER = cint(1)
  # SSL_get_error return codes.
  SSL_ERROR_NONE = cint(0)
  SSL_ERROR_SSL = cint(1)
  SSL_ERROR_WANT_READ = cint(2)
  SSL_ERROR_WANT_WRITE = cint(3)
  SSL_ERROR_SYSCALL = cint(5)
  SSL_ERROR_ZERO_RETURN = cint(6)
  # SSL_CTX_ctrl / SSL_ctrl command numbers (openssl/ssl.h).
  SSL_CTRL_SET_TLSEXT_HOSTNAME = cint(55)
  SSL_CTRL_SET_MIN_PROTO_VERSION = cint(123)
  SSL_CTRL_SET_MAX_PROTO_VERSION = cint(124)
  SSL_CTRL_SET_GROUPS_LIST = cint(92)
  SSL_CTRL_SET_SIGALGS_LIST = cint(98)
  SSL_CTRL_GET_NEGOTIATED_GROUP = cint(134)
  TLSEXT_NAMETYPE_host_name = clong(0)
  # X509_V_OK.
  X509_V_OK = clong(0)

const
  TLS1_VERSION* = 0x0301
  TLS1_1_VERSION* = 0x0302
  TLS1_2_VERSION* = 0x0303
  TLS1_3_VERSION* = 0x0304

proc TLS_client_method(): pointer {.cdecl, importc: "TLS_client_method", dynlib: sslLib.}
proc TLS_server_method(): pointer {.cdecl, importc: "TLS_server_method", dynlib: sslLib.}
proc SSL_CTX_new(meth: pointer): pointer {.cdecl, importc: "SSL_CTX_new", dynlib: sslLib.}
proc SSL_CTX_free(ctx: nil pointer) {.cdecl, importc: "SSL_CTX_free", dynlib: sslLib.}
proc SSL_CTX_set_verify(ctx: nil pointer; mode: cint; cb: nil pointer) {.cdecl, importc: "SSL_CTX_set_verify", dynlib: sslLib.}
proc SSL_CTX_set_default_verify_paths(ctx: nil pointer): cint {.cdecl, importc: "SSL_CTX_set_default_verify_paths", dynlib: sslLib.}
proc SSL_CTX_load_verify_locations(ctx: nil pointer; caFile: cstring; caPath: nil cstring): cint {.cdecl, importc: "SSL_CTX_load_verify_locations", dynlib: sslLib.}
proc SSL_CTX_use_certificate_chain_file(ctx: nil pointer; file: cstring): cint {.cdecl, importc: "SSL_CTX_use_certificate_chain_file", dynlib: sslLib.}
proc SSL_CTX_use_PrivateKey_file(ctx: nil pointer; file: cstring; typ: cint): cint {.cdecl, importc: "SSL_CTX_use_PrivateKey_file", dynlib: sslLib.}
proc SSL_CTX_check_private_key(ctx: nil pointer): cint {.cdecl, importc: "SSL_CTX_check_private_key", dynlib: sslLib.}
proc SSL_CTX_set_cipher_list(ctx: nil pointer; str: cstring): cint {.cdecl, importc: "SSL_CTX_set_cipher_list", dynlib: sslLib.}
proc SSL_CTX_set_ciphersuites(ctx: nil pointer; str: cstring): cint {.cdecl, importc: "SSL_CTX_set_ciphersuites", dynlib: sslLib.}
proc SSL_CTX_set_alpn_protos(ctx: nil pointer; protos: pointer; len: cuint): cint {.cdecl, importc: "SSL_CTX_set_alpn_protos", dynlib: sslLib.}
proc SSL_CTX_set_alpn_select_cb(ctx: nil pointer; cb: pointer; arg: nil pointer) {.cdecl, importc: "SSL_CTX_set_alpn_select_cb", dynlib: sslLib.}
proc SSL_select_next_proto(outp: ptr pointer; outl: ptr uint8; server: pointer; slen: cuint; client: pointer; clen: cuint): cint {.cdecl, importc: "SSL_select_next_proto", dynlib: sslLib.}
proc SSL_CTX_ctrl(ctx: nil pointer; cmd: cint; larg: clong; parg: nil pointer): clong {.cdecl, importc: "SSL_CTX_ctrl", dynlib: sslLib.}
proc OBJ_nid2sn(n: cint): nil pointer {.cdecl, importc: "OBJ_nid2sn", dynlib: cryptoLib.}

proc SSL_new(ctx: nil pointer): pointer {.cdecl, importc: "SSL_new", dynlib: sslLib.}
proc SSL_free(ssl: nil pointer) {.cdecl, importc: "SSL_free", dynlib: sslLib.}
proc SSL_set_fd(ssl: nil pointer; fd: cint): cint {.cdecl, importc: "SSL_set_fd", dynlib: sslLib.}
proc SSL_ctrl(ssl: nil pointer; cmd: cint; larg: clong; parg: pointer): clong {.cdecl, importc: "SSL_ctrl", dynlib: sslLib.}
proc SSL_set1_host(ssl: nil pointer; host: cstring): cint {.cdecl, importc: "SSL_set1_host", dynlib: sslLib.}
proc SSL_set_connect_state(ssl: nil pointer) {.cdecl, importc: "SSL_set_connect_state", dynlib: sslLib.}
proc SSL_set_accept_state(ssl: nil pointer) {.cdecl, importc: "SSL_set_accept_state", dynlib: sslLib.}
proc SSL_connect(ssl: nil pointer): cint {.cdecl, importc: "SSL_connect", dynlib: sslLib.}
proc SSL_accept(ssl: nil pointer): cint {.cdecl, importc: "SSL_accept", dynlib: sslLib.}
proc SSL_do_handshake(ssl: nil pointer): cint {.cdecl, importc: "SSL_do_handshake", dynlib: sslLib.}
proc SSL_read(ssl: nil pointer; buf: pointer; num: cint): cint {.cdecl, importc: "SSL_read", dynlib: sslLib.}
proc SSL_write(ssl: nil pointer; buf: pointer; num: cint): cint {.cdecl, importc: "SSL_write", dynlib: sslLib.}
proc SSL_get_error(ssl: nil pointer; ret: cint): cint {.cdecl, importc: "SSL_get_error", dynlib: sslLib.}
proc SSL_shutdown(ssl: nil pointer): cint {.cdecl, importc: "SSL_shutdown", dynlib: sslLib.}
proc SSL_pending(ssl: nil pointer): cint {.cdecl, importc: "SSL_pending", dynlib: sslLib.}
proc SSL_get_verify_result(ssl: nil pointer): clong {.cdecl, importc: "SSL_get_verify_result", dynlib: sslLib.}
proc SSL_get_version(ssl: nil pointer): cstring {.cdecl, importc: "SSL_get_version", dynlib: sslLib.}
proc SSL_get_current_cipher(ssl: nil pointer): pointer {.cdecl, importc: "SSL_get_current_cipher", dynlib: sslLib.}
proc SSL_CIPHER_get_name(c: pointer): cstring {.cdecl, importc: "SSL_CIPHER_get_name", dynlib: sslLib.}
proc SSL_get0_alpn_selected(ssl: nil pointer; data: ptr pointer; len: ptr cuint) {.cdecl, importc: "SSL_get0_alpn_selected", dynlib: sslLib.}

proc ERR_get_error(): culong {.cdecl, importc: "ERR_get_error", dynlib: cryptoLib.}
proc ERR_error_string_n(e: culong; buf: pointer; len: csize_t) {.cdecl, importc: "ERR_error_string_n", dynlib: cryptoLib.}
proc ERR_clear_error() {.cdecl, importc: "ERR_clear_error", dynlib: cryptoLib.}

# --- Session resumption + SNI virtual hosting + peer cert inspection ---------
const
  # SSL_CTX_ctrl / SSL_CTX_callback_ctrl command numbers (openssl/tls1.h).
  SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = cint(53)
  SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = cint(54)
  # openssl/ssl.h.
  SSL_CTRL_SET_SESS_CACHE_MODE = cint(44)
  TLSEXT_NAMETYPE_host_name_int = cint(0)
  # SSL_TLSEXT_ERR_* (openssl/tls1.h).
  SSL_TLSEXT_ERR_OK = cint(0)
  # Session cache modes (openssl/ssl.h).
  SSL_SESS_CACHE_OFF* = 0x0000
  SSL_SESS_CACHE_CLIENT* = 0x0001
  SSL_SESS_CACHE_SERVER* = 0x0002
  SSL_SESS_CACHE_BOTH* = 0x0003
  # NID for the certificate CommonName field (openssl/obj_mac.h).
  NID_commonName = cint(13)

# Session resumption.
proc SSL_get1_session(ssl: nil pointer): pointer {.cdecl, importc: "SSL_get1_session", dynlib: sslLib.}
proc SSL_set_session(ssl: nil pointer; session: nil pointer): cint {.cdecl, importc: "SSL_set_session", dynlib: sslLib.}
proc SSL_SESSION_free(session: nil pointer) {.cdecl, importc: "SSL_SESSION_free", dynlib: sslLib.}
proc SSL_session_reused(ssl: nil pointer): cint {.cdecl, importc: "SSL_session_reused", dynlib: sslLib.}
# SNI virtual hosting.
proc SSL_CTX_callback_ctrl(ctx: nil pointer; cmd: cint; fp: pointer): clong {.cdecl, importc: "SSL_CTX_callback_ctrl", dynlib: sslLib.}
proc SSL_set_SSL_CTX(ssl: nil pointer; ctx: nil pointer): pointer {.cdecl, importc: "SSL_set_SSL_CTX", dynlib: sslLib.}
proc SSL_get_servername(ssl: nil pointer; typ: cint): cstring {.cdecl, importc: "SSL_get_servername", dynlib: sslLib.}
# Peer certificate inspection.
proc SSL_get1_peer_certificate(ssl: nil pointer): pointer {.cdecl, importc: "SSL_get1_peer_certificate", dynlib: sslLib.}
proc X509_free(x: nil pointer) {.cdecl, importc: "X509_free", dynlib: cryptoLib.}
proc X509_get_subject_name(x: nil pointer): pointer {.cdecl, importc: "X509_get_subject_name", dynlib: cryptoLib.}
proc X509_NAME_get_text_by_NID(name: nil pointer; nid: cint; buf: pointer; len: cint): cint {.cdecl, importc: "X509_NAME_get_text_by_NID", dynlib: cryptoLib.}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc cstrToString(cs: cstring): string =
  ## nimony has no `$`(cstring); walk the NUL-terminated bytes ourselves.
  result = ""
  if cast[pointer](cs) == nil: return
  let p = cast[ptr UncheckedArray[char]](cs)
  var i = 0
  while p[i] != '\0':
    result.add p[i]
    inc i

proc isValid*(ctx: TlsContext): bool =
  ctx.handle != nil

proc isValid*(t: TlsSocket): bool =
  t.ssl != nil

proc lastTlsError*(): string =
  ## Pop and format the most recent OpenSSL error, or "" when the queue is
  ## empty. Useful for logging a failed handshake.
  let e = ERR_get_error()
  if e == culong(0):
    return ""
  var buf = default(array[256, char])
  ERR_error_string_n(e, addr buf[0], csize_t(buf.len))
  result = ""
  var i = 0
  while i < buf.len and buf[i] != '\0':
    result.add buf[i]
    inc i

proc classify(ssl: nil pointer; ret: cint): TlsStatus =
  ## Map an OpenSSL return value + SSL_get_error into a TlsStatus.
  let err = SSL_get_error(ssl, ret)
  if err == SSL_ERROR_NONE:
    tlsOk
  elif err == SSL_ERROR_WANT_READ:
    tlsWantRead
  elif err == SSL_ERROR_WANT_WRITE:
    tlsWantWrite
  elif err == SSL_ERROR_ZERO_RETURN:
    tlsClosed
  elif err == SSL_ERROR_SYSCALL:
    # A clean transport EOF before close_notify shows up here with ret == 0.
    if ret == cint(0): tlsClosed else: tlsError
  else:
    tlsError

# ---------------------------------------------------------------------------
# Context construction / configuration
# ---------------------------------------------------------------------------

proc newTlsClientContext*(verify = true): TlsContext =
  ## A client context. When `verify` is true (default) the server certificate
  ## chain is validated against the system trust store; set false only for
  ## testing against self-signed certs (or call `setVerify`/`loadVerifyLocations`).
  let meth = TLS_client_method()
  let ctx = SSL_CTX_new(meth)
  result = TlsContext(handle: ctx, mode: tlsClient)
  if ctx == nil:
    return result
  if verify:
    discard SSL_CTX_set_default_verify_paths(ctx)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
  else:
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)

proc newTlsServerContext*(certChainFile: string; keyFile: string): TlsContext =
  ## A server context loading a PEM certificate chain and its private key.
  ## Returns an invalid context (`isValid` false) if either file fails to load
  ## or the key does not match the certificate.
  var certc = certChainFile
  var keyc = keyFile
  let meth = TLS_server_method()
  let ctx = SSL_CTX_new(meth)
  result = TlsContext(handle: ctx, mode: tlsServer)
  if ctx == nil:
    return result
  if SSL_CTX_use_certificate_chain_file(ctx, toCString(certc)) != cint(1):
    SSL_CTX_free(ctx)
    result.handle = nil
    return result
  if SSL_CTX_use_PrivateKey_file(ctx, toCString(keyc), SSL_FILETYPE_PEM) != cint(1):
    SSL_CTX_free(ctx)
    result.handle = nil
    return result
  if SSL_CTX_check_private_key(ctx) != cint(1):
    SSL_CTX_free(ctx)
    result.handle = nil
    return result

proc setVerifyPeer*(ctx: TlsContext; enabled: bool) =
  ## Turn peer certificate verification on or off.
  if not ctx.isValid: return
  if enabled:
    SSL_CTX_set_verify(ctx.handle, SSL_VERIFY_PEER, nil)
  else:
    SSL_CTX_set_verify(ctx.handle, SSL_VERIFY_NONE, nil)

proc loadVerifyLocations*(ctx: TlsContext; caFile: string): bool =
  ## Trust an extra CA bundle / cert file (PEM). Returns success.
  if not ctx.isValid: return false
  var f = caFile
  SSL_CTX_load_verify_locations(ctx.handle, toCString(f), nil) == cint(1)

proc useDefaultVerifyPaths*(ctx: TlsContext): bool =
  ## (Re)load the system default trust store. Returns success.
  if not ctx.isValid: return false
  SSL_CTX_set_default_verify_paths(ctx.handle) == cint(1)

proc setCipherList*(ctx: TlsContext; ciphers: string): bool =
  ## Restrict the TLS 1.2-and-below cipher list (OpenSSL cipher string).
  if not ctx.isValid: return false
  var c = ciphers
  SSL_CTX_set_cipher_list(ctx.handle, toCString(c)) == cint(1)

proc setCipherSuites*(ctx: TlsContext; suites: string): bool =
  ## Restrict the TLS 1.3 cipher suites (colon-separated suite names).
  if not ctx.isValid: return false
  var s = suites
  SSL_CTX_set_ciphersuites(ctx.handle, toCString(s)) == cint(1)

proc setMinVersion*(ctx: TlsContext; version: int): bool =
  ## Floor the negotiated protocol version (e.g. `TLS1_2_VERSION`).
  if not ctx.isValid: return false
  SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_MIN_PROTO_VERSION, clong(version), nil) == clong(1)

proc setMaxVersion*(ctx: TlsContext; version: int): bool =
  ## Cap the negotiated protocol version.
  if not ctx.isValid: return false
  SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_MAX_PROTO_VERSION, clong(version), nil) == clong(1)

const
  PostQuantumGroups* = "X25519MLKEM768:X25519:P-256:P-384"
    ## A sensible post-quantum-hybrid preference: ML-KEM-768 combined with
    ## X25519 first, classical curves behind it. Requires OpenSSL >= 3.5 (the
    ## system 3.0.x here does not know ML-KEM); see vendor/build-openssl.sh.

proc setGroups*(ctx: TlsContext; groups: string): bool =
  ## Set the key-exchange groups to offer, most preferred first, as a
  ## colon-separated list (e.g. `PostQuantumGroups`). This is how post-quantum
  ## key exchange is turned on: with OpenSSL 3.5+ the name `X25519MLKEM768`
  ## resolves to the ML-KEM hybrid, and a peer that does not know it simply
  ## negotiates the next group in the list.
  if not ctx.isValid: return false
  var g = groups
  SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_GROUPS_LIST, clong(0),
               cast[pointer](toCString(g))) == clong(1)

proc setSigAlgs*(ctx: TlsContext; algs: string): bool =
  ## Set the signature algorithms to advertise, most preferred first
  ## (e.g. "ECDSA+SHA256:RSA-PSS+SHA256").
  if not ctx.isValid: return false
  var a = algs
  SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_SIGALGS_LIST, clong(0),
               cast[pointer](toCString(a))) == clong(1)

proc alpnWire(protocols: seq[string]): string =
  ## Build the ALPN wire format: each protocol as a 1-byte length prefix + name.
  result = ""
  var i = 0
  while i < protocols.len:
    let p = protocols[i]
    if p.len > 0 and p.len <= 255:
      result.add char(p.len)
      var j = 0
      while j < p.len:
        result.add p[j]
        inc j
    inc i

proc setAlpnProtocols*(ctx: TlsContext; protocols: seq[string]): bool =
  ## (Client) Advertise an ALPN protocol list, e.g. `@["h2", "http/1.1"]`.
  if not ctx.isValid: return false
  var wire = alpnWire(protocols)
  if wire.len == 0: return false
  # SSL_CTX_set_alpn_protos returns 0 on success (note: inverted convention).
  # `toCString` yields a pointer to the string's bytes; the length is passed
  # explicitly so NUL-termination is irrelevant (and the wire has no NULs:
  # length prefixes are 1..255 and protocol names are ASCII).
  SSL_CTX_set_alpn_protos(ctx.handle, cast[pointer](toCString(wire)), cuint(wire.len)) == cint(0)

# Server-side per-context state: SNI virtual-host cert selection + ALPN.
#
# Two servers in one process must not clobber each other, so the server-side
# wire state lives in a registry indexed per `TlsContext` rather than in a
# single process-global. Each server `TlsContext` that gains SNI certs or an
# ALPN preference is assigned a `stateId` (1-based; 0 = unassigned). The C
# callbacks receive that id as their `arg` and look their state up in the
# registry, so no two contexts share mutable wire state. `gServerAlpnWire`
# remains only as a legacy fallback when a callback carries no valid id.
type
  SniEntry = object
    host: string
    ctx: nil pointer        ## a child SSL_CTX holding this host's cert + key

  ServerState = object
    alpnWire: string        ## server ALPN preference, wire format ("" = none)
    entries: seq[SniEntry]  ## per-SNI-hostname child contexts

var gServerStates: seq[ServerState] = @[]
var gServerAlpnWire = ""    # legacy fallback (arg-less callbacks)

proc argToStateIndex(arg: pointer): int =
  ## Decode a callback `arg` (a 1-based stateId) into a 0-based registry index,
  ## or -1 when there is no valid state.
  let raw = cast[int](arg)
  if raw <= 0 or raw > gServerStates.len: return -1
  raw - 1

proc alpnSelectCb(ssl: nil pointer; outp: ptr pointer; outl: ptr uint8;
                  inp: pointer; inl: cuint; arg: pointer): cint {.cdecl.} =
  let idx = argToStateIndex(arg)
  var wire = gServerAlpnWire
  if idx >= 0 and gServerStates[idx].alpnWire.len > 0:
    wire = gServerStates[idx].alpnWire
  if wire.len == 0:
    return cint(3)   # SSL_TLSEXT_ERR_NOACK
  let rc = SSL_select_next_proto(outp, outl,
                                 cast[pointer](toCString(wire)),
                                 cuint(wire.len), inp, inl)
  if rc == cint(1):  # OPENSSL_NPN_NEGOTIATED
    return cint(0)   # SSL_TLSEXT_ERR_OK
  cint(3)            # SSL_TLSEXT_ERR_NOACK

proc sniServernameCb(ssl: nil pointer; al: ptr cint; arg: pointer): cint {.cdecl.} =
  ## At handshake time pick the child SSL_CTX whose hostname matches the
  ## client's SNI, so the matching certificate is presented. No match keeps the
  ## context's default certificate.
  let idx = argToStateIndex(arg)
  if idx < 0: return SSL_TLSEXT_ERR_OK
  let cs = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name_int)
  if cast[pointer](cs) == nil: return SSL_TLSEXT_ERR_OK
  let name = cstrToString(cs)
  var i = 0
  while i < gServerStates[idx].entries.len:
    if gServerStates[idx].entries[i].host == name:
      discard SSL_set_SSL_CTX(ssl, gServerStates[idx].entries[i].ctx)
      return SSL_TLSEXT_ERR_OK
    inc i
  SSL_TLSEXT_ERR_OK

proc ensureServerState(ctx: var TlsContext): int =
  ## Return the 0-based registry index for `ctx`, allocating (and wiring up the
  ## SNI servername callback on the underlying SSL_CTX) on first use.
  if ctx.stateId > 0 and ctx.stateId <= gServerStates.len:
    return ctx.stateId - 1
  gServerStates.add ServerState(alpnWire: "", entries: newSeq[SniEntry](0))
  ctx.stateId = gServerStates.len          # 1-based
  discard SSL_CTX_callback_ctrl(ctx.handle, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                                sniServernameCb)
  discard SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,
                       clong(0), cast[pointer](ctx.stateId))
  ctx.stateId - 1

proc setAlpnServer*(ctx: var TlsContext; protocols: seq[string]): bool =
  ## (Server) Negotiate ALPN by selecting the server's most-preferred protocol
  ## from the client's offer, e.g. `@["h2", "http/1.1"]`. Unlike
  ## `setAlpnProtocols` (which only advertises, for clients), this registers the
  ## server selection callback so `negotiatedAlpn` reflects the chosen protocol.
  ## The preference is stored per-context, so multiple servers in one process
  ## don't clobber each other.
  if not ctx.isValid: return false
  let wire = alpnWire(protocols)
  if wire.len == 0: return false
  let idx = ensureServerState(ctx)
  gServerStates[idx].alpnWire = wire
  gServerAlpnWire = wire     # keep legacy fallback in sync for single-server use
  SSL_CTX_set_alpn_select_cb(ctx.handle, alpnSelectCb, cast[pointer](ctx.stateId))
  true

proc addCertificate*(ctx: var TlsContext; hostname: string;
                     certChainFile: string; keyFile: string): bool =
  ## (Server) Register an additional certificate + key to serve when a client's
  ## SNI hostname matches `hostname` (TLS virtual hosting). The certificate
  ## given to `newTlsServerContext` remains the default fallback for connections
  ## whose SNI matches nothing here (or omit SNI). Returns false if the context
  ## isn't a valid server context or the cert/key fails to load or mismatch.
  if not ctx.isValid or ctx.mode != tlsServer: return false
  let child = SSL_CTX_new(TLS_server_method())
  if child == nil: return false
  var cf = certChainFile
  var kf = keyFile
  if SSL_CTX_use_certificate_chain_file(child, toCString(cf)) != cint(1):
    SSL_CTX_free(child)
    return false
  if SSL_CTX_use_PrivateKey_file(child, toCString(kf), SSL_FILETYPE_PEM) != cint(1):
    SSL_CTX_free(child)
    return false
  if SSL_CTX_check_private_key(child) != cint(1):
    SSL_CTX_free(child)
    return false
  let idx = ensureServerState(ctx)
  gServerStates[idx].entries.add SniEntry(host: hostname, ctx: child)
  true

proc close*(ctx: var TlsContext) =
  ## Free the underlying `SSL_CTX` and any per-SNI child contexts.
  if ctx.stateId > 0 and ctx.stateId <= gServerStates.len:
    let idx = ctx.stateId - 1
    var i = 0
    while i < gServerStates[idx].entries.len:
      if gServerStates[idx].entries[i].ctx != nil:
        SSL_CTX_free(gServerStates[idx].entries[i].ctx)
        gServerStates[idx].entries[i].ctx = nil
      inc i
    gServerStates[idx].entries = newSeq[SniEntry](0)
    gServerStates[idx].alpnWire = ""
    ctx.stateId = 0
  if ctx.handle != nil:
    SSL_CTX_free(ctx.handle)
    ctx.handle = nil

proc freeContext*(ctx: var TlsContext) =
  ## Unambiguous alias for `close(TlsContext)` — use at call sites that also
  ## import `net` (whose `Socket` also has a `close`), where `ctx.close()` is
  ## reported ambiguous.
  close(ctx)

# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

proc handshake*(t: var TlsSocket): TlsStatus =
  ## Drive (or resume) the handshake. On a blocking socket this returns `tlsOk`
  ## once complete; on a non-blocking socket it may return `tlsWantRead` /
  ## `tlsWantWrite`, in which case call again after the socket is ready.
  if not t.isValid: return tlsError
  if t.handshakeDone: return tlsOk
  ERR_clear_error()
  let rc = SSL_do_handshake(t.ssl)
  if rc == cint(1):
    t.handshakeDone = true
    return tlsOk
  result = classify(t.ssl, rc)
  if result == tlsOk:
    t.handshakeDone = true

proc wrapClient*(ctx: TlsContext; socket: Socket; serverName: string;
                 session = TlsSession(handle: nil)): TlsSocket =
  ## Begin a client TLS session over an already-connected `socket`. Sets SNI and
  ## the verification hostname to `serverName`, then runs the handshake (blocking
  ## sockets complete here; use `handshake` to resume a non-blocking one). Check
  ## `handshakeDone` / `isValid` on the result.
  ##
  ## Pass a `session` captured from an earlier connection (via `getSession`) to
  ## attempt TLS 1.3 resumption; check `sessionReused` on the result once the
  ## handshake completes.
  result = TlsSocket(socket: socket, ssl: nil, handshakeDone: false)
  if not ctx.isValid or not socket.isValid: return result
  let ssl = SSL_new(ctx.handle)
  if ssl == nil: return result
  if SSL_set_fd(ssl, cint(socket.handle)) != cint(1):
    SSL_free(ssl)
    return result
  SSL_set_connect_state(ssl)
  # Offer a prior session for resumption (before the handshake starts).
  if session.handle != nil:
    discard SSL_set_session(ssl, session.handle)
  # SNI + hostname verification.
  var host = serverName
  if host.len > 0:
    discard SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                     cast[pointer](toCString(host)))
    discard SSL_set1_host(ssl, toCString(host))
  result.ssl = ssl
  discard handshake(result)

proc connectTls*(ctx: TlsContext; host: string; port: int;
                 session = TlsSession(handle: nil)): TlsSocket =
  ## Ergonomic client entry: resolve `host`, open a TCP connection, and run the
  ## client TLS handshake with SNI + hostname verification set to `host`.
  ## Blocking; check `handshakeDone` / `isValid` on the result. The returned
  ## socket keeps `ctx` alive via OpenSSL's refcount, so `ctx` may be closed
  ## afterwards without tearing down live connections. Pass a `session` to
  ## attempt resumption (see `getSession` / `sessionReused`).
  result = TlsSocket(socket: invalidSocket(), ssl: nil, handshakeDone: false)
  if not ctx.isValid: return result
  var raw = 0'u32
  if not resolveTcp4(host, raw): return result
  let sock = Socket(handle: connectTcp4(raw, port))
  if not sock.isValid: return result
  result = wrapClient(ctx, sock, host, session)

proc wrapServer*(ctx: TlsContext; socket: Socket): TlsSocket =
  ## Begin a server TLS session over an accepted `socket` and run the handshake.
  result = TlsSocket(socket: socket, ssl: nil, handshakeDone: false)
  if not ctx.isValid or not socket.isValid: return result
  let ssl = SSL_new(ctx.handle)
  if ssl == nil: return result
  if SSL_set_fd(ssl, cint(socket.handle)) != cint(1):
    SSL_free(ssl)
    return result
  SSL_set_accept_state(ssl)
  result.ssl = ssl
  discard handshake(result)

# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

proc tlsReadInto*(t: var TlsSocket; buf: pointer; len: int; status: var TlsStatus): int =
  ## Read up to `len` bytes of plaintext. Returns the count (>0) with
  ## `status == tlsOk`; returns 0 with `tlsClosed` at end of stream, or with
  ## `tlsWantRead`/`tlsWantWrite` on a non-blocking socket, or `tlsError`.
  if not t.isValid:
    status = tlsError
    return -1
  if len <= 0:
    status = tlsOk
    return 0
  ERR_clear_error()
  let n = SSL_read(t.ssl, buf, cint(len))
  if n > cint(0):
    status = tlsOk
    return int(n)
  status = classify(t.ssl, n)
  0

proc tlsWriteFrom*(t: var TlsSocket; buf: pointer; len: int; status: var TlsStatus): int =
  ## Write up to `len` bytes of plaintext. Returns the count accepted (>0) with
  ## `status == tlsOk`, or 0 with a want/closed/error status.
  if not t.isValid:
    status = tlsError
    return -1
  if len <= 0:
    status = tlsOk
    return 0
  ERR_clear_error()
  let n = SSL_write(t.ssl, buf, cint(len))
  if n > cint(0):
    status = tlsOk
    return int(n)
  status = classify(t.ssl, n)
  0

proc pending*(t: TlsSocket): int =
  ## Bytes already decrypted and buffered inside OpenSSL (not yet visible to a
  ## raw socket poll). A caller polling the fd must drain these first.
  if not t.isValid: return 0
  int(SSL_pending(t.ssl))

proc recv*(t: var TlsSocket; maxBytes: int): string =
  ## Read up to `maxBytes` bytes of plaintext into a string (blocking-socket
  ## convenience). Stops at EOF or when a read makes no progress.
  result = ""
  if not t.isValid: return result
  var remaining = maxBytes
  if remaining < 0: remaining = 0
  var buf = default(array[8192, char])
  var st = tlsOk
  while remaining > 0:
    var chunk = buf.len
    if chunk > remaining: chunk = remaining
    let n = tlsReadInto(t, addr buf[0], chunk, st)
    if n <= 0: break
    var i = 0
    while i < n:
      result.add buf[i]
      inc i
    remaining = remaining - n

proc readAll*(t: var TlsSocket): string =
  ## Read plaintext until the peer closes the TLS session (blocking-socket
  ## convenience).
  result = ""
  if not t.isValid: return result
  var buf = default(array[8192, char])
  var st = tlsOk
  while true:
    let n = tlsReadInto(t, addr buf[0], buf.len, st)
    if n <= 0: break
    var i = 0
    while i < n:
      result.add buf[i]
      inc i

proc send*(t: var TlsSocket; data: string): int =
  ## Write the whole string (blocking-socket convenience). Returns bytes sent;
  ## a short return signals a closed / errored session.
  if not t.isValid: return 0
  var buf = default(array[8192, char])
  var total = 0
  var st = tlsOk
  while total < data.len:
    var n = 0
    while n < buf.len and total + n < data.len:
      buf[n] = data[total + n]
      inc n
    let written = tlsWriteFrom(t, addr buf[0], n, st)
    if written <= 0:
      return total
    total = total + written
  return total

proc sendAll*(t: var TlsSocket; data: string): bool =
  send(t, data) == data.len

# ---------------------------------------------------------------------------
# Connection info
# ---------------------------------------------------------------------------

proc protocolVersion*(t: TlsSocket): string =
  ## The negotiated protocol, e.g. "TLSv1.3".
  if not t.isValid: return ""
  cstrToString(SSL_get_version(t.ssl))

proc cipherName*(t: TlsSocket): string =
  ## The negotiated cipher suite name.
  if not t.isValid: return ""
  let c = SSL_get_current_cipher(t.ssl)
  if c == nil: return ""
  cstrToString(SSL_CIPHER_get_name(c))

proc negotiatedAlpn*(t: TlsSocket): string =
  ## The ALPN protocol the peer selected (e.g. "h2"), or "" if none.
  if not t.isValid: return ""
  var data = cast[pointer](0)
  var length = cuint(0)
  SSL_get0_alpn_selected(t.ssl, addr data, addr length)
  if data == nil or length == cuint(0): return ""
  let bytes = cast[ptr UncheckedArray[char]](data)
  result = ""
  var i = 0
  while i < int(length):
    result.add bytes[i]
    inc i

proc negotiatedGroupId*(t: TlsSocket): int =
  ## The NID of the key-exchange group the handshake actually settled on, or 0.
  if not t.isValid: return 0
  int(SSL_ctrl(t.ssl, SSL_CTRL_GET_NEGOTIATED_GROUP, clong(0), cast[pointer](0)))

const
  TlsextNidUnknown = 0x1000000
    ## OpenSSL ORs this into the "negotiated group" for any group that has no
    ## object NID — which is every post-quantum hybrid. The low 16 bits are then
    ## the raw IANA TLS supported-group codepoint.

proc groupCodepointName(code: int): string =
  ## Names for the groups OpenSSL cannot name itself (RFC 8446 registry).
  case code
  of 0x11EB: "SecP256r1MLKEM768"
  of 0x11EC: "X25519MLKEM768"
  of 0x11ED: "SecP384r1MLKEM1024"
  of 0x0200: "MLKEM512"
  of 0x0201: "MLKEM768"
  of 0x0202: "MLKEM1024"
  else: ""

proc toHex4(v: int): string =
  const digits = "0123456789abcdef"
  result = "0x"
  var shift = 12
  while shift >= 0:
    result.add digits[(v shr shift) and 0xf]
    shift = shift - 4

proc negotiatedGroup*(t: TlsSocket): string =
  ## The key-exchange group actually negotiated, by name (e.g. "X25519MLKEM768"
  ## or "x25519"). Setting a preference is only half of a knob — this is how a
  ## caller confirms what the peer agreed to, rather than assuming.
  ##
  ## Post-quantum groups have no OpenSSL object NID, so they arrive as
  ## `TLSEXT_nid_unknown | codepoint` and are decoded from the IANA registry
  ## here; anything still unrecognised comes back as "group-0xNNNN" rather than
  ## as an empty string, so a caller is never left guessing.
  let nid = negotiatedGroupId(t)
  if nid == 0: return ""
  if (nid and TlsextNidUnknown) != 0:
    let code = nid and 0xFFFF
    let named = groupCodepointName(code)
    if named.len > 0: return named
    return "group-" & toHex4(code)
  let sn = OBJ_nid2sn(cint(nid))
  if sn == nil: return ""
  result = ""
  let bytes = cast[ptr UncheckedArray[char]](sn)
  var i = 0
  while i < 128 and bytes[i] != '\0':
    result.add bytes[i]
    inc i

proc verifyOk*(t: TlsSocket): bool =
  ## True when the peer certificate chain verified (X509_V_OK). Meaningful only
  ## when the context requested verification.
  if not t.isValid: return false
  SSL_get_verify_result(t.ssl) == X509_V_OK

proc verifyResultCode*(t: TlsSocket): int =
  ## The raw X509 verification result code (0 == X509_V_OK).
  if not t.isValid: return -1
  int(SSL_get_verify_result(t.ssl))

proc peerCertCommonName*(t: TlsSocket): string =
  ## The CommonName (CN) of the peer's leaf certificate subject, or "" if there
  ## is no peer certificate / no CN. Handy on a client to confirm which cert a
  ## multi-cert (SNI) server selected.
  result = ""
  if not t.isValid: return result
  let cert = SSL_get1_peer_certificate(t.ssl)
  if cert == nil: return result
  let name = X509_get_subject_name(cert)
  if name == nil:
    X509_free(cert)
    return result
  var buf = default(array[256, char])
  let n = X509_NAME_get_text_by_NID(name, NID_commonName, addr buf[0], cint(buf.len))
  if n > cint(0):
    var i = 0
    while i < int(n) and i < buf.len and buf[i] != '\0':
      result.add buf[i]
      inc i
  X509_free(cert)

# ---------------------------------------------------------------------------
# Session resumption
# ---------------------------------------------------------------------------

proc setSessionCacheMode*(ctx: TlsContext; mode: int): bool =
  ## Set the SSL_CTX session-cache mode (one of `SSL_SESS_CACHE_*`). On a client
  ## context, `SSL_SESS_CACHE_CLIENT` keeps captured sessions available for
  ## reuse; on a server, `SSL_SESS_CACHE_SERVER` (the default) enables the
  ## internal cache. Returns false only if the context is invalid.
  if not ctx.isValid: return false
  discard SSL_CTX_ctrl(ctx.handle, SSL_CTRL_SET_SESS_CACHE_MODE, clong(mode), nil)
  true

proc enableClientSessionCache*(ctx: TlsContext): bool =
  ## Convenience: turn on client-side session caching so `getSession` reliably
  ## captures a resumable TLS 1.3 session (including its ticket).
  setSessionCacheMode(ctx, SSL_SESS_CACHE_CLIENT)

proc getSession*(t: TlsSocket): TlsSession =
  ## Capture the current session as a resumable handle (refcounted; free it with
  ## `freeSession`). Call after the handshake completed and — for TLS 1.3 — after
  ## at least one `recv`, so the server's session ticket has been processed.
  ## The returned session is invalid (`isValid` false) if none is available.
  result = TlsSession(handle: nil)
  if not t.isValid or not t.handshakeDone: return result
  result = TlsSession(handle: SSL_get1_session(t.ssl))

proc isValid*(s: TlsSession): bool =
  s.handle != nil

proc freeSession*(s: var TlsSession) =
  ## Release a captured session.
  if s.handle != nil:
    SSL_SESSION_free(s.handle)
    s.handle = nil

proc sessionReused*(t: TlsSocket): bool =
  ## True when the just-completed handshake resumed a prior session (a session
  ## supplied via `wrapClient` / `connectTls` was accepted by the peer).
  if not t.isValid: return false
  SSL_session_reused(t.ssl) == cint(1)

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

proc closeTls*(t: var TlsSocket; closeSocket = true) =
  ## Send close_notify, free the `SSL`, and (by default) close the socket.
  if t.ssl != nil:
    discard SSL_shutdown(t.ssl)
    SSL_free(t.ssl)
    t.ssl = nil
  t.handshakeDone = false
  if closeSocket:
    t.socket.close()

# ---------------------------------------------------------------------------
# Policy as data
#
# The setters above are the mechanism; `TlsConfig` is the policy. Splitting
# them is what lets something that does not own the context — a server entry
# point, a process-wide default, a per-virtual-host override — still say what
# the TLS should look like.
# ---------------------------------------------------------------------------

proc note(report: var TlsConfigReport; name: string; succeeded: bool) =
  if succeeded:
    report.applied = report.applied + 1
  else:
    report.failed = report.failed + 1
    if report.firstFailure.len == 0:
      report.firstFailure = name

proc applyTlsConfig*(ctx: var TlsContext; cfg: TlsConfig): TlsConfigReport =
  ## Apply every set field of `cfg` to an existing context, reporting what
  ## OpenSSL accepted. Unset fields are not touched, so applying
  ## `defaultTlsConfig()` is a no-op.
  ##
  ## Two fields are deliberately not consumed here, for the same reason
  ## `TcpOpts.backlog` is not: they are not context settings.
  ## `certChainFile`/`keyFile` belong to context *construction*, and
  ## `serverName` is per-connection SNI, chosen at `wrapClient` time.
  result = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  if not ctx.isValid:
    note(result, "context", false)
    return result

  # Trust configuration first: verification mode has to be in place before any
  # handshake, and loading a CA bundle after switching verification off would
  # read as an inconsistency in the report.
  if cfg.useSystemTrust == optOn:
    note(result, "useSystemTrust", useDefaultVerifyPaths(ctx))
  if cfg.caFile.len > 0:
    note(result, "caFile", loadVerifyLocations(ctx, cfg.caFile))
  if cfg.verifyPeer != optUnset:
    setVerifyPeer(ctx, cfg.verifyPeer == optOn)
    note(result, "verifyPeer", true)

  if cfg.minVersion != TlsUnset:
    note(result, "minVersion", setMinVersion(ctx, cfg.minVersion))
  if cfg.maxVersion != TlsUnset:
    note(result, "maxVersion", setMaxVersion(ctx, cfg.maxVersion))
  if cfg.cipherList.len > 0:
    note(result, "cipherList", setCipherList(ctx, cfg.cipherList))
  if cfg.cipherSuites.len > 0:
    note(result, "cipherSuites", setCipherSuites(ctx, cfg.cipherSuites))
  if cfg.groups.len > 0:
    note(result, "groups", setGroups(ctx, cfg.groups))
  if cfg.sigAlgs.len > 0:
    note(result, "sigAlgs", setSigAlgs(ctx, cfg.sigAlgs))
  if cfg.sessionCacheMode != TlsUnset:
    note(result, "sessionCacheMode", setSessionCacheMode(ctx, cfg.sessionCacheMode))

  # ALPN means two different things by role: a client advertises a list, a
  # server registers a callback that selects from the client's offer. One
  # field, because from a caller's point of view it is one decision.
  if cfg.alpn.len > 0:
    if ctx.mode == tlsServer:
      note(result, "alpn", setAlpnServer(ctx, cfg.alpn))
    else:
      note(result, "alpn", setAlpnProtocols(ctx, cfg.alpn))

proc newTlsClientContext*(cfg: TlsConfig; report: var TlsConfigReport): TlsContext =
  ## A client context built from a policy. Note that verification is whatever
  ## the config says and nothing more: unlike the `verify = true` overload this
  ## does not quietly load the system trust store on your behalf, which is why
  ## `defaultClientConfig()` sets both fields explicitly.
  report = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  let ctx = SSL_CTX_new(TLS_client_method())
  result = TlsContext(handle: ctx, mode: tlsClient)
  if ctx == nil:
    note(report, "SSL_CTX_new", false)
    return result
  report = applyTlsConfig(result, cfg)

proc newTlsServerContext*(cfg: TlsConfig; report: var TlsConfigReport): TlsContext =
  ## A server context built from a policy. The certificate pair comes from the
  ## config, so a server entry point can be handed one value instead of a cert
  ## path, a key path, and no way to say anything else.
  report = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  if not hasCertificate(cfg):
    note(report, "certificate", false)
    return TlsContext(handle: nil, mode: tlsServer)
  result = newTlsServerContext(cfg.certChainFile, cfg.keyFile)
  if not result.isValid:
    note(report, "certificate", false)
    return result
  report = applyTlsConfig(result, cfg)
