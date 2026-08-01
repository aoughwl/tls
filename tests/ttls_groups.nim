## ttls_groups.nim — key-exchange group selection, including post-quantum.
##
## Setting a preference is only half a knob; the other half is reading back what
## the peer actually agreed to. This drives a real loopback handshake and asserts
## the negotiated group by name.
##
## With the system OpenSSL 3.0.x, ML-KEM does not exist and the handshake falls
## back to a classical curve — that is the correct behaviour and the test says so
## rather than failing. Run against the vendored 3.5 to get the PQ result:
##
##   LD_LIBRARY_PATH=vendor/lib ./ttls_groups

import std/syncio
import net
import tls

proc check(cond: bool; label: string) =
  if not cond:
    echo "FAIL: ", label
    quit(1)

proc main =
  initNet()

  var sctx = newTlsServerContext("cert.pem", "key.pem")
  check(sctx.isValid, "server context (needs cert.pem/key.pem in cwd)")
  var cctx = newTlsClientContext(false)
  check(cctx.isValid, "client context")

  # Offer the PQ hybrid first, classical behind it. On 3.0 the ML-KEM name is
  # unknown; OpenSSL rejects the whole list, so fall back to a classical one.
  var pq = setGroups(cctx, PostQuantumGroups) and setGroups(sctx, PostQuantumGroups)
  if not pq:
    echo "NOTE: ML-KEM groups rejected — OpenSSL < 3.5, using classical groups"
    check(setGroups(cctx, "X25519:P-256"), "client classical groups")
    check(setGroups(sctx, "X25519:P-256"), "server classical groups")

  check(setSigAlgs(cctx, "ECDSA+SHA256:RSA-PSS+SHA256"), "client sigalgs")

  let server = listen(localhostIpv4(), 0)
  check(server.isValid, "listen")
  let port = localEndpoint(server).port

  let csock = connect(localhostIpv4(), port)
  check(csock.isValid, "connect")
  let asock = accept(server)
  check(asock.isValid, "accept")

  # non-blocking BEFORE wrapping: wrapClient/wrapServer drive the handshake
  # themselves, so on blocking sockets the first one to be wrapped waits forever
  # for a peer that has not been wrapped yet.
  check(setNonBlocking(csock) and setNonBlocking(asock), "nonblocking")
  var cs = wrapClient(cctx, csock, "localhost")
  var ss = wrapServer(sctx, asock)

  # pump both sides of the handshake on one thread
  var i = 0
  while i < 2000 and not (cs.handshakeDone and ss.handshakeDone):
    if not cs.handshakeDone: discard handshake(cs)
    if not ss.handshakeDone: discard handshake(ss)
    inc i
  check(cs.handshakeDone and ss.handshakeDone, "handshake completed")

  let group = negotiatedGroup(cs)
  echo "negotiated group: ", group, " id=", negotiatedGroupId(cs),
       "  (", protocolVersion(cs), " / ", cipherName(cs), ")"
  check(group.len > 0, "a group name is readable")

  if pq:
    check(group == "X25519MLKEM768",
          "expected the PQ hybrid, negotiated " & group)
    echo "POST_QUANTUM=yes"
  else:
    echo "POST_QUANTUM=no"

  closeTls(cs)
  closeTls(ss)
  close(server)
  shutdownNet()
  echo "ttls_groups: all checks passed"

main()
