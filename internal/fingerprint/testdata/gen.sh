#!/usr/bin/env bash
# Regenerates the ADR-0002 fingerprint vectors (docs/adr/0002-public-key-identity.md).
#
# The committed outputs ARE the test inputs. CI never runs this script, and
# regenerating certificates/CSRs changes their bytes (signatures are randomised),
# which is harmless: the tests pin key identities, which do not change, and read
# certificate fingerprints from vectors.json written below.
#
# Requires OpenSSL >= 3.5 (ML-DSA with seeded key generation).
set -euo pipefail
# Git Bash on Windows rewrites "/CN=..." arguments into Windows paths.
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"

openssl version | grep -Eq '^OpenSSL 3\.([5-9]|[1-9][0-9])' || {
  echo "OpenSSL >= 3.5 required, found: $(openssl version)" >&2; exit 1; }

SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
V=vectors
U=unsupported
rm -rf "$V" "$U"
mkdir -p "$V" "$U"

sha() { openssl dgst -sha256 -r | cut -d' ' -f1; }

# ── positive vectors: published or seeded private keys ──────────────────────
mkdir -p "$V/rsa-2048" "$V/ecdsa-p256" "$V/ed25519" "$V/ml-dsa-44" "$V/ml-dsa-65" "$V/ml-dsa-87"

# RFC 9500 §2.2 testRSA2048 (PKCS#1)
cat > "$V/rsa-2048/key.pem" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----
EOF

# RFC 9500 §2.3 testECCP256 (SEC1)
cat > "$V/ecdsa-p256/key.pem" <<'EOF'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49
AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END EC PRIVATE KEY-----
EOF

# RFC 8410 §10.3 example Ed25519 key (PKCS#8)
cat > "$V/ed25519/key.pem" <<'EOF'
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
EOF

for p in 44 65 87; do
  openssl genpkey -algorithm "ML-DSA-$p" -pkeyopt "hexseed:$SEED" \
    -provparam ml-dsa.output_formats=seed-only -out "$V/ml-dsa-$p/key.pem"
done

derive() {
  local d=$1 name
  name=$(basename "$d")
  case "$name" in ml-dsa-*) fmt=(-provparam ml-dsa.output_formats=seed-only) ;; *) fmt=() ;; esac
  openssl pkey "${fmt[@]}" -in "$d/key.pem" -out "$d/pkcs8.pem"
  openssl pkey -in "$d/key.pem" -pubout -out "$d/spki.pem"
  openssl pkey -in "$d/key.pem" -pubout -outform DER -out "$d/spki.der"
  openssl req -new -x509 -key "$d/key.pem" -subj "/CN=trustsmith ADR-0002 vector $name" \
    -days 36500 -set_serial 1 -out "$d/cert.pem"
  openssl req -new -key "$d/key.pem" -subj "/CN=trustsmith ADR-0002 vector $name" -out "$d/csr.pem"
}

hexof() { xxd -p "$1" | tr -d '\n'; }
fromhex() { xxd -r -p > "$1"; }

# ── two-scheme vectors: non-canonical encodings of the same keys ────────────
mkdir -p "$V/rsa-2048-no-null" "$V/ecdsa-p256-compressed"

# ── unsupported-for-identity keys (random; only their classification matters) ─
unsupported() {
  openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 | openssl pkey -pubout -outform DER -out "$U/rsa-pss.der"
  openssl genpkey -algorithm X25519 | openssl pkey -pubout -outform DER -out "$U/x25519.der"
  openssl genpkey -algorithm ED448 | openssl pkey -pubout -outform DER -out "$U/ed448.der"
  openssl ecparam -name secp256k1 -genkey -noout | openssl ec -pubout -outform DER -out "$U/ec-secp256k1.der" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -param_enc explicit | openssl ec -pubout -outform DER -param_enc explicit -out "$U/ec-p256-explicit-params.der" 2>/dev/null
  openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -out "$U/dsa-params.pem"
  openssl genpkey -paramfile "$U/dsa-params.pem" | openssl pkey -pubout -outform DER -out "$U/dsa.der"
  rm -f "$U/dsa-params.pem"
}

main() {
  for d in rsa-2048 ecdsa-p256 ed25519 ml-dsa-44 ml-dsa-65 ml-dsa-87; do derive "$V/$d"; done

  # RSA: drop the explicit NULL AlgorithmIdentifier parameters (outer length 0x122 → 0x120).
  local h rest
  h=$(hexof "$V/rsa-2048/spki.der")
  [ "${h:0:38}" = "30820122300d06092a864886f70d0101010500" ] || { echo "unexpected RSA SPKI prefix" >&2; exit 1; }
  rest=${h:38}
  printf '%s' "30820120300b06092a864886f70d010101${rest}" | fromhex "$V/rsa-2048-no-null/spki.der"

  # P-256: compress the point (04‖X‖Y → 02|03‖X).
  local pt x ylast prefix
  h=$(hexof "$V/ecdsa-p256/spki.der")
  pt=${h: -130}; x=${pt:2:64}; ylast=${pt: -2}
  if (( 0x$ylast & 1 )); then prefix=03; else prefix=02; fi
  printf '%s' "3039301306072a8648ce3d020106082a8648ce3d030107032200${prefix}${x}" | fromhex "$V/ecdsa-p256-compressed/spki.der"

  unsupported

  {
    echo '{'
    echo '  "adr": "ADR-0002",'
    echo "  \"generated_with\": \"$(openssl version | cut -d' ' -f1-2)\","
    echo '  "positive": ['
    local first=1 src
    for d in rsa-2048 ecdsa-p256 ed25519 ml-dsa-44 ml-dsa-65 ml-dsa-87; do
      case $d in
        rsa-2048) src="RFC 9500 testRSA2048" ;;
        ecdsa-p256) src="RFC 9500 testECCP256" ;;
        ed25519) src="RFC 8410 section 10.3" ;;
        *) src="seed $SEED" ;;
      esac
      [ $first = 1 ] || echo ','
      first=0
      printf '    {"name": "%s", "source": "%s", "key_id": "%s", "cert_sha256": "%s", "pin_sha256": "%s"}' \
        "$d" "$src" \
        "$(sha < "$V/$d/spki.der")" \
        "$(openssl x509 -in "$V/$d/cert.pem" -outform DER | sha)" \
        "$(openssl dgst -sha256 -binary "$V/$d/spki.der" | openssl base64 -A)"
    done
    echo ''
    echo '  ],'
    echo '  "two_scheme": ['
    printf '    {"name": "rsa-2048-no-null", "canonical_sibling": "rsa-2048", "encoded_sha256": "%s"},\n' "$(sha < "$V/rsa-2048-no-null/spki.der")"
    printf '    {"name": "ecdsa-p256-compressed", "canonical_sibling": "ecdsa-p256", "encoded_sha256": "%s"}\n' "$(sha < "$V/ecdsa-p256-compressed/spki.der")"
    echo '  ]'
    echo '}'
  } > vectors.json
}

main
echo "wrote $(pwd)/vectors.json"
