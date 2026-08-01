## ttls_config.nim — TLS policy as a value, checked against a real handshake.
##
## The interesting assertion is the version cap. A config record that "applied
## successfully" but never reached OpenSSL would still let both ends negotiate
## TLS 1.3, so the test pins `maxVersion` to TLS 1.2 on the *client config
## only* and asserts the negotiated version is TLS 1.2. Nothing about that can
## pass unless the field travelled from the record into `SSL_CTX`.

import std/syncio
import std/os
import net
import tls

const
  certPath = "/tmp/aoughwl_tlscfg_cert.pem"
  keyPath = "/tmp/aoughwl_tlscfg_key.pem"

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc pumpHandshake(c: var TlsSocket; s: var TlsSocket) =
  var spins = 0
  while (not c.handshakeDone or not s.handshakeDone) and spins < 10000:
    let cs = handshake(c)
    let ss = handshake(s)
    check(cs != tlsError, "client handshake error: " & lastTlsError())
    check(ss != tlsError, "server handshake error: " & lastTlsError())
    inc spins
  check(c.handshakeDone, "client handshake did not complete")
  check(s.handshakeDone, "server handshake did not complete")

proc main =
  initNet()

  # --- The merge rule ----------------------------------------------------
  var process = defaultClientConfig()
  process.minVersion = TLS1_2_VERSION
  var perServer = defaultTlsConfig()
  perServer.maxVersion = TLS1_2_VERSION

  let merged = merge(process, perServer)
  check(merged.verifyPeer == optOn, "unset field inherits from base")
  check(merged.minVersion == TLS1_2_VERSION, "base field survives")
  check(merged.maxVersion == TLS1_2_VERSION, "override lands")

  var relaxed = defaultTlsConfig()
  relaxed.verifyPeer = optOff
  let final = merge(merged, relaxed)
  check(final.verifyPeer == optOff, "an override can turn verification off")
  check(final.minVersion == TLS1_2_VERSION, "unrelated field survives")

  check(isEmpty(defaultTlsConfig()), "the empty config sets nothing")
  check(not isEmpty(defaultClientConfig()), "the client config sets something")
  check(insecureClientConfig().verifyPeer == optOff, "insecure means insecure")
  check(not hasCertificate(defaultTlsConfig()), "no cert pair by default")
  check(hasCertificate(defaultServerConfig("c.pem", "k.pem")), "cert pair present")

  let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " & keyPath &
            " -out " & certPath &
            " -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1"
  if execShellCmd(cmd) != 0:
    echo "SKIP: openssl CLI unavailable; cannot generate test cert"
    quit(0)

  # --- The empty config is a verified no-op ------------------------------
  var probe = newTlsClientContext(verify = false)
  check(probe.isValid, "probe context")
  let noop = applyTlsConfig(probe, defaultTlsConfig())
  check(noop.applied == 0, "empty config touched nothing")
  check(ok(noop), "empty config reports ok")
  probe.close()

  # --- Contexts built entirely from policy -------------------------------
  var serverCfg = defaultServerConfig(certPath, keyPath)
  serverCfg.alpn = @["h2", "http/1.1"]
  var serverReport = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  var sctx = newTlsServerContext(serverCfg, serverReport)
  check(sctx.isValid, "server context from config: " & serverReport.firstFailure)
  check(ok(serverReport), "server config applied: " & serverReport.firstFailure)

  var clientCfg = insecureClientConfig()   # self-signed cert under test
  clientCfg.alpn = @["http/1.1"]
  clientCfg.maxVersion = TLS1_2_VERSION    # <- the property this test turns on
  var clientReport = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  var cctx = newTlsClientContext(clientCfg, clientReport)
  check(cctx.isValid, "client context from config")
  check(ok(clientReport), "client config applied: " & clientReport.firstFailure)

  var lsock = listen(0)
  check(lsock.isValid, "listen failed")
  let port = localEndpoint(lsock).port
  check(port > 0, "no ephemeral port")

  let craw = connectLocalhost(port)
  check(craw.isValid, "client connect failed")
  let sraw = accept(lsock)
  check(sraw.isValid, "server accept failed")
  check(setNonBlocking(craw), "client nonblocking failed")
  check(setNonBlocking(sraw), "server nonblocking failed")

  var c = wrapClient(cctx, craw, "localhost")
  var s = wrapServer(sctx, sraw)
  check(c.isValid and s.isValid, "wrap failed")
  pumpHandshake(c, s)

  # The version cap came from a record, not from a setter call on the context.
  let ver = c.protocolVersion()
  check(ver == "TLSv1.2",
        "maxVersion from the config did not reach OpenSSL; negotiated " & ver)

  # ALPN was expressed as one field and applied differently per role: the
  # client advertised it, the server selected from the offer.
  let proto = c.negotiatedAlpn()
  check(proto == "http/1.1",
        "ALPN from the config did not negotiate; got '" & proto & "'")

  check(setBlocking(craw, true), "client reblock failed")
  check(setBlocking(sraw, true), "server reblock failed")
  let ping = "cfg\n"
  check(c.sendAll(ping), "client send failed")
  check(s.recv(ping.len) == ping, "server did not receive the payload")

  # --- A failure is reported, not swallowed ------------------------------
  var badCfg = defaultTlsConfig()
  badCfg.caFile = "/nonexistent/definitely-not-a-ca-bundle.pem"
  var badCtx = newTlsClientContext(verify = false)
  let badReport = applyTlsConfig(badCtx, badCfg)
  check(not ok(badReport), "a missing CA file is a failure")
  check(badReport.firstFailure == "caFile", "the failing setting is named")
  badCtx.close()

  var noCert = TlsConfigReport(applied: 0, failed: 0, firstFailure: "")
  let noCertCtx = newTlsServerContext(defaultTlsConfig(), noCert)
  check(not noCertCtx.isValid, "a server config with no cert pair fails")
  check(noCert.firstFailure == "certificate", "and says why")

  c.closeTls()
  s.closeTls()
  lsock.close()
  cctx.close()
  sctx.close()
  shutdownNet()

  echo "ttls_config: all checks passed (negotiated ", ver, " / ", proto, ")"

main()
