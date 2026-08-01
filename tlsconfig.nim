## tlsconfig.nim — the TLS config record.
##
## `tls` has a wide and genuinely capable setter surface, but until now the only
## way to reach it was to hold the `TlsContext` and call fifteen procs against
## it in the right order. That is fine when you build the context yourself, and
## impossible when something else does: `serveTls` constructed and owned its own
## context, so every knob in this library was unreachable from a server. The
## `TlsContext` overloads fixed the ownership half of that. This is the other
## half — the *policy* half — a value describing what a context should be,
## which can be written once and handed anywhere.
##
## Same rules as `TcpOpts`, deliberately: `optUnset` and the empty string mean
## "leave it alone", so `defaultTlsConfig()` applied to a context is a verified
## no-op, and `merge` implements the scope ladder by overriding only what was
## actually set. The tri-state is `TriOpt` from `tcp`, reused rather than
## re-invented, so one merge idiom covers the whole stack.

import net

const
  TlsUnset* = -1
    ## Sentinel for the integer fields.

type
  TlsConfig* = object
    ## Declarative TLS policy for a context, in either role. Fields that apply
    ## to only one role are ignored in the other rather than being an error —
    ## a process-wide base config can then carry both.
    verifyPeer*: TriOpt         ## validate the peer's certificate chain
    useSystemTrust*: TriOpt     ## load the platform trust store
    caFile*: string             ## additional PEM CA bundle to trust
    cipherList*: string         ## TLS 1.2-and-below cipher string
    cipherSuites*: string       ## TLS 1.3 suite names
    minVersion*: int            ## e.g. TLS1_2_VERSION
    maxVersion*: int
    groups*: string             ## key-exchange groups, e.g. PostQuantumGroups
    sigAlgs*: string            ## signature algorithms to advertise
    alpn*: seq[string]          ## protocols; advertised on a client, selected on a server
    certChainFile*: string      ## server certificate chain (PEM)
    keyFile*: string            ## server private key (PEM)
    sessionCacheMode*: int      ## SSL_SESS_CACHE_*
    serverName*: string         ## SNI hostname to send; "" uses the connect host

  TlsConfigReport* = object
    ## What `applyTlsConfig` managed to do. Same shape as `TcpOptsReport`, and
    ## the same reason: a setting OpenSSL rejected — a cipher string with no
    ## overlap, a CA file that is not there — must not vanish into a `discard`.
    applied*: int
    failed*: int
    firstFailure*: string

proc defaultTlsConfig*(): TlsConfig =
  ## The empty policy. Applying it changes nothing, which is what makes it a
  ## safe base for every merge.
  TlsConfig(
    verifyPeer: optUnset, useSystemTrust: optUnset, caFile: "",
    cipherList: "", cipherSuites: "", minVersion: TlsUnset, maxVersion: TlsUnset,
    groups: "", sigAlgs: "", alpn: @[], certChainFile: "", keyFile: "",
    sessionCacheMode: TlsUnset, serverName: "")

proc defaultClientConfig*(): TlsConfig =
  ## Exactly what `newTlsClientContext(verify = true)` has always done, written
  ## as data: verify the peer against the system trust store.
  result = defaultTlsConfig()
  result.verifyPeer = optOn
  result.useSystemTrust = optOn

proc insecureClientConfig*(): TlsConfig =
  ## Verification off. Named for what it is, so it cannot be reached by
  ## accident and reads as a deliberate choice at the call site — this is the
  ## setting that turns TLS into obfuscation.
  result = defaultTlsConfig()
  result.verifyPeer = optOff
  result.useSystemTrust = optUnset

proc defaultServerConfig*(certChainFile: string; keyFile: string): TlsConfig =
  ## What `newTlsServerContext(cert, key)` has always done.
  result = defaultTlsConfig()
  result.certChainFile = certChainFile
  result.keyFile = keyFile

proc merge*(base: TlsConfig; over: TlsConfig): TlsConfig =
  ## Field set in `over` wins; field left unset inherits. Composing a
  ## process-wide TLS policy with a per-server one is repeated application.
  result = base
  if over.verifyPeer != optUnset: result.verifyPeer = over.verifyPeer
  if over.useSystemTrust != optUnset: result.useSystemTrust = over.useSystemTrust
  if over.caFile.len > 0: result.caFile = over.caFile
  if over.cipherList.len > 0: result.cipherList = over.cipherList
  if over.cipherSuites.len > 0: result.cipherSuites = over.cipherSuites
  if over.minVersion != TlsUnset: result.minVersion = over.minVersion
  if over.maxVersion != TlsUnset: result.maxVersion = over.maxVersion
  if over.groups.len > 0: result.groups = over.groups
  if over.sigAlgs.len > 0: result.sigAlgs = over.sigAlgs
  if over.alpn.len > 0: result.alpn = over.alpn
  if over.certChainFile.len > 0: result.certChainFile = over.certChainFile
  if over.keyFile.len > 0: result.keyFile = over.keyFile
  if over.sessionCacheMode != TlsUnset: result.sessionCacheMode = over.sessionCacheMode
  if over.serverName.len > 0: result.serverName = over.serverName

proc hasCertificate*(cfg: TlsConfig): bool =
  ## A server context cannot be built without both halves of the pair.
  cfg.certChainFile.len > 0 and cfg.keyFile.len > 0

proc isEmpty*(cfg: TlsConfig): bool =
  ## True when applying this config to a context would touch nothing.
  cfg.verifyPeer == optUnset and cfg.useSystemTrust == optUnset and
    cfg.caFile.len == 0 and cfg.cipherList.len == 0 and
    cfg.cipherSuites.len == 0 and cfg.minVersion == TlsUnset and
    cfg.maxVersion == TlsUnset and cfg.groups.len == 0 and
    cfg.sigAlgs.len == 0 and cfg.alpn.len == 0 and
    cfg.sessionCacheMode == TlsUnset

proc ok*(report: TlsConfigReport): bool =
  ## Every setting the config asked for was accepted.
  report.failed == 0
