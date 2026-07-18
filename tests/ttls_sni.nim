## ttls_sni.nim — per-SNI multi-certificate virtual hosting over loopback.
##
## A single server `TlsContext` holds three self-signed certs: a default
## (CN=default.test) plus two SNI-specific ones (CN=alpha.test, CN=beta.test)
## registered with `addCertificate`. Two client connections send different SNI
## host names; each asserts (via the peer cert's CommonName) that the server
## selected the matching certificate, and a third with an unknown SNI falls back
## to the default cert.

import std/syncio
import std/os
import net
import tls

const
  dir = "/tmp"
  defCert = dir & "/aoughwl_sni_default_cert.pem"
  defKey  = dir & "/aoughwl_sni_default_key.pem"
  aCert   = dir & "/aoughwl_sni_alpha_cert.pem"
  aKey    = dir & "/aoughwl_sni_alpha_key.pem"
  bCert   = dir & "/aoughwl_sni_beta_cert.pem"
  bKey    = dir & "/aoughwl_sni_beta_key.pem"

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc genCert(certFile: string; keyFile: string; cn: string): bool =
  let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " & keyFile &
            " -out " & certFile & " -days 1 -nodes -subj /CN=" & cn &
            " >/dev/null 2>&1"
  execShellCmd(cmd) == 0

proc pump(c: var TlsSocket; s: var TlsSocket): bool =
  var spins = 0
  while (not c.handshakeDone or not s.handshakeDone) and spins < 10000:
    let cs = handshake(c)
    let ss = handshake(s)
    if cs == tlsError or ss == tlsError: return false
    inc spins
  c.handshakeDone and s.handshakeDone

proc connectSni(cctx: TlsContext; sctx: TlsContext; lsock: Socket;
                port: int; sni: string; cn: var string): bool =
  ## Open one loopback connection whose client SNI is `sni`; on success set `cn`
  ## to the CommonName of the certificate the server presented.
  cn = ""
  let craw = connectLocalhost(port)
  if not craw.isValid: return false
  let sraw = accept(lsock)
  if not sraw.isValid: return false
  if not setNonBlocking(craw): return false
  if not setNonBlocking(sraw): return false
  var c = wrapClient(cctx, craw, sni)
  var s = wrapServer(sctx, sraw)
  if not c.isValid or not s.isValid: return false
  if not pump(c, s): return false
  cn = c.peerCertCommonName()
  c.closeTls()
  s.closeTls()
  true

proc main =
  initNet()

  if not genCert(defCert, defKey, "default.test") or
     not genCert(aCert, aKey, "alpha.test") or
     not genCert(bCert, bKey, "beta.test"):
    echo "SKIP: openssl CLI unavailable; cannot generate test certs"
    quit(0)

  var sctx = newTlsServerContext(defCert, defKey)
  check(sctx.isValid, "server ctx invalid: " & lastTlsError())
  check(sctx.addCertificate("alpha.test", aCert, aKey), "addCertificate alpha")
  check(sctx.addCertificate("beta.test", bCert, bKey), "addCertificate beta")

  var cctx = newTlsClientContext(verify = false)
  check(cctx.isValid, "client ctx invalid")

  var lsock = listen(0)
  check(lsock.isValid, "listen failed")
  let port = localEndpoint(lsock).port
  check(port > 0, "no ephemeral port")

  var cn = ""
  check(connectSni(cctx, sctx, lsock, port, "alpha.test", cn),
        "alpha connection failed: " & lastTlsError())
  check(cn == "alpha.test", "SNI alpha.test got wrong cert CN: '" & cn & "'")

  check(connectSni(cctx, sctx, lsock, port, "beta.test", cn),
        "beta connection failed: " & lastTlsError())
  check(cn == "beta.test", "SNI beta.test got wrong cert CN: '" & cn & "'")

  # Unknown SNI must fall back to the default certificate.
  check(connectSni(cctx, sctx, lsock, port, "unknown.test", cn),
        "fallback connection failed: " & lastTlsError())
  check(cn == "default.test", "unknown SNI did not fall back to default: '" & cn & "'")

  lsock.close()
  cctx.close()
  sctx.close()
  shutdownNet()

  echo "SNI selected: alpha.test / beta.test / default.test (fallback)"
  echo "ttls_sni: all checks passed"

main()
