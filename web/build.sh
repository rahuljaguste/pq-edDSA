#!/usr/bin/env bash
# Build the browser demo. Run from anywhere; writes web/pkg/.
#
#   ./web/build.sh && (cd web && python3 -m http.server 8742)
#   open http://localhost:8742/
#
# Do NOT add -C target-feature=+simd128. binius64's wasm32 SIMD module does not compile
# at the pinned revision (fix submitted as binius-zk/binius64#1993), and with the fix
# applied it is worth under 1% on this circuit — measured, 1670 ms against 1682 ms. The
# module aliases the portable field arithmetic; only its lane splitting uses intrinsics.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

command -v wasm-bindgen >/dev/null || {
	echo "wasm-bindgen not found. Install with:" >&2
	echo "  cargo install wasm-bindgen-cli --version 0.2.126" >&2
	exit 1
}

# SPIKE BRANCH: WIDE=1 selects GF(2^256)/SHA-512 from the fork.
features=""
[ "${WIDE:-}" = "1" ] && features="--features wide"
cargo build --release --target wasm32-unknown-unknown -p pq-eddsa-wasm $features
wasm-bindgen --target web --out-dir web/pkg --no-typescript \
	target/wasm32-unknown-unknown/release/pq_eddsa_wasm.wasm

echo
echo "built web/pkg/ — serve it over HTTP, not file://, which fails CORS:"
echo "  (cd web && python3 -m http.server 8742)"
echo "  open http://localhost:8742/            # the demo"
echo "  open http://localhost:8742/bench.html?auto=1   # the benchmark"
