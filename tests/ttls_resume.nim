## ttls_resume.nim — TLS 1.3 session resumption over loopback, driven on a
## single thread by pumping both ends' non-blocking handshakes.
##
## Does a full handshake, exchanges data (so the server's NewSessionTicket is
## delivered and processed on the client), captures the session with
## `getSession`, then opens a SECOND connection passing that session to
## `wrapClient` and asserts `sessionReused` is true on the resumed handshake.

import std/syncio
import std/os
import net
import tls

const
  certPath = "/tmp/aoughwl_tls_resume_cert.pem"
  keyPath = "/tmp/aoughwl_tls_resume_key.pem"

proc check(cond: bool; msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)

proc pump(c: var TlsSocket; s: var TlsSocket): bool =
  ## Alternately drive both non-blocking handshakes until both complete.
  var spins = 0
  while (not c.handshakeDone or not s.handshakeDone) and spins < 10000:
    let cs = handshake(c)
    let ss = handshake(s)
    if cs == tlsError or ss == tlsError: return false
    inc spins
  c.handshakeDone and s.handshakeDone

proc exchange(c: var TlsSocket; s: var TlsSocket): bool =
  ## Lockstep ping/pong over the established channel. The client's recv here
  ## processes any pending NewSessionTicket records.
  if not c.sendAll("ping\n"): return false
  if s.recv(5) != "ping\n": return false
  if not s.sendAll("pong\n"): return false
  c.recv(5) == "pong\n"

proc main =
  initNet()

  let cmd = "openssl req -x509 -newkey rsa:2048 -keyout " & keyPath &
            " -out " & certPath &
            " -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1"
  if execShellCmd(cmd) != 0:
    echo "SKIP: openssl CLI unavailable; cannot generate test cert"
    quit(0)

  var sctx = newTlsServerContext(certPath, keyPath)
  check(sctx.isValid, "server ctx invalid: " & lastTlsError())
  # Server-side tickets are on by default in OpenSSL 3; make the server cache
  # explicit (non-breaking, just documents intent).
  check(sctx.setSessionCacheMode(SSL_SESS_CACHE_SERVER), "server cache mode")

  var cctx = newTlsClientContext(verify = false)
  check(cctx.isValid, "client ctx invalid")
  check(cctx.enableClientSessionCache(), "client cache mode")

  var lsock = listen(0)
  check(lsock.isValid, "listen failed")
  let port = localEndpoint(lsock).port
  check(port > 0, "no ephemeral port")

  # --- connection 1: full handshake, capture the session -------------------
  let craw1 = connectLocalhost(port)
  check(craw1.isValid, "conn1 client connect failed")
  let sraw1 = accept(lsock)
  check(sraw1.isValid, "conn1 server accept failed")
  check(setNonBlocking(craw1), "conn1 client nonblocking")
  check(setNonBlocking(sraw1), "conn1 server nonblocking")

  var c1 = wrapClient(cctx, craw1, "localhost")
  var s1 = wrapServer(sctx, sraw1)
  check(c1.isValid and s1.isValid, "conn1 wrap failed")
  check(pump(c1, s1), "conn1 handshake did not complete: " & lastTlsError())

  check(setBlocking(craw1, true), "conn1 client reblock")
  check(setBlocking(sraw1, true), "conn1 server reblock")
  check(exchange(c1, s1), "conn1 data exchange failed")

  check(not c1.sessionReused(), "conn1 must NOT be a resumption")
  var sess = c1.getSession()
  check(sess.isValid, "failed to capture session from conn1")

  c1.closeTls()
  s1.closeTls()

  # --- connection 2: resume the captured session ---------------------------
  let craw2 = connectLocalhost(port)
  check(craw2.isValid, "conn2 client connect failed")
  let sraw2 = accept(lsock)
  check(sraw2.isValid, "conn2 server accept failed")
  check(setNonBlocking(craw2), "conn2 client nonblocking")
  check(setNonBlocking(sraw2), "conn2 server nonblocking")

  var c2 = wrapClient(cctx, craw2, "localhost", sess)
  var s2 = wrapServer(sctx, sraw2)
  check(c2.isValid and s2.isValid, "conn2 wrap failed")
  check(pump(c2, s2), "conn2 handshake did not complete: " & lastTlsError())

  check(setBlocking(craw2, true), "conn2 client reblock")
  check(setBlocking(sraw2, true), "conn2 server reblock")
  check(exchange(c2, s2), "conn2 data exchange failed")

  check(c2.sessionReused(), "conn2 handshake did NOT resume the session")

  let ver = c2.protocolVersion()
  check(ver == "TLSv1.3", "expected TLSv1.3, got: " & ver)

  c2.closeTls()
  s2.closeTls()
  freeSession(sess)
  lsock.close()
  cctx.close()
  sctx.close()
  shutdownNet()

  echo "resumed ", ver, " session (sessionReused=true on 2nd connection)"
  echo "ttls_resume: all checks passed"

main()
