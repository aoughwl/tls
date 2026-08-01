#!/usr/bin/env bash
# Build a vendored OpenSSL 3.5.x into aoughwl-tls/vendor.
#
# The system OpenSSL here is 3.0.13, which has NEITHER of the two things this
# stack wants from a modern TLS library:
#   * post-quantum key exchange (ML-KEM / X25519MLKEM768) — 3.5 ships it in the
#     default provider, so `setGroups` can offer a PQ hybrid;
#   * a QUIC API — 3.0 has none, which is why the HTTP/3 stack had to use
#     GnuTLS via ngtcp2 instead of our own tls layer.
#
# Same stance as quic/build-nghttp3.sh: vendored, self-contained, and the
# consumer picks it up only if it is present.
set -euo pipefail
VER="${OPENSSL_VERSION:-3.5.7}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/src"
PREFIX="$HERE"

mkdir -p "$SRC"
cd "$SRC"

TARBALL="openssl-$VER.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  echo "== fetching OpenSSL $VER =="
  curl -fsSL -o "$TARBALL" \
    "https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz"
fi

if [[ ! -d "openssl-$VER" ]]; then
  echo "== unpacking =="
  tar xzf "$TARBALL"
fi

cd "openssl-$VER"
if [[ ! -f Makefile ]]; then
  echo "== configuring =="
  # shared libs, no docs (they dominate the build time), own rpath so the
  # vendored libs never shadow the system ones for anything else
  ./Configure linux-x86_64 shared \
    --prefix="$PREFIX" \
    --openssldir="$PREFIX/ssl" \
    --libdir=lib \
    -Wl,-rpath,"$PREFIX/lib" \
    no-docs
fi

echo "== building (this is the slow part) =="
make -j"$(nproc)"
echo "== installing to $PREFIX =="
make install_sw

"$PREFIX/bin/openssl" version
echo "built: $PREFIX/lib/libssl.so.3"
