#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Generate SCP11 OCE + CA-KLOC material using OpenSSL (NIST P-256, ECDSA/SHA-256).

Outputs (GlobalPlatform naming convention):
  SK.CA-KLOC.ECDSA.pem
  PK.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.der
  SK.OCE.ECKA.pem
  PK.OCE.ECKA.pem
  CERT.OCE.ECKA.pem
  CERT.OCE.ECKA.der
  CERT.OCE.ECKA.CHAIN.pem      (CERT.OCE.ECKA + CERT.CA-KLOC.ECDSA)
  CERT.OCE.ECKA.CHAIN.der      (concatenated DER: OCE then CA)
  CA-KLOC.ID.hex               (SHA-1 over CA subject public key info)

Usage:
  scp11-oce-ca-openssl.sh [options]

Options:
  -o, --out-dir <dir>      Output directory (default: ./scp11-oce-ca)
  -d, --days <n>           Validity in days (default: 3650 = 10 years)
  -c, --curve <name>       EC curve (default: prime256v1)
  -f, --force              Overwrite output directory if it exists

  --cn <value>             CA subject CN (default: GP CA)
  --ou <value>             CA subject OU (default: GP Trust Network)
  --org <value>            CA subject O  (default: GP)
  --country <value>        CA subject C  (default: UK)

  --oce-cn <value>         OCE subject CN (default: GP OCE)
  --oce-ou <value>         OCE subject OU (default: same as CA OU)
  --oce-org <value>        OCE subject O  (default: same as CA O)
  --oce-country <value>    OCE subject C  (default: same as CA C)

  -h, --help               Show this help

Examples:
  scp11-oce-ca-openssl.sh
  scp11-oce-ca-openssl.sh -o out/scp11 --cn "My GP CA" --oce-cn "My OCE"
EOF
}

require_arg() {
    if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == -* ]]; then
        echo "Missing value for $1" >&2
        exit 2
    fi
}

OUT_DIR="./scp11-oce-ca"
DAYS=3650
CURVE="prime256v1"
FORCE=0

CA_CN="GP CA"
CA_OU="GP Trust Network"
CA_O="GP"
CA_C="UK"

OCE_CN="GP OCE"
OCE_OU=""
OCE_O=""
OCE_C=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out-dir)
            require_arg "$@"
            OUT_DIR="$2"
            shift 2
            ;;
        -d|--days)
            require_arg "$@"
            DAYS="$2"
            shift 2
            ;;
        -c|--curve)
            require_arg "$@"
            CURVE="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=1
            shift
            ;;
        --cn)
            require_arg "$@"
            CA_CN="$2"
            shift 2
            ;;
        --ou)
            require_arg "$@"
            CA_OU="$2"
            shift 2
            ;;
        --org)
            require_arg "$@"
            CA_O="$2"
            shift 2
            ;;
        --country)
            require_arg "$@"
            CA_C="$2"
            shift 2
            ;;
        --oce-cn)
            require_arg "$@"
            OCE_CN="$2"
            shift 2
            ;;
        --oce-ou)
            require_arg "$@"
            OCE_OU="$2"
            shift 2
            ;;
        --oce-org)
            require_arg "$@"
            OCE_O="$2"
            shift 2
            ;;
        --oce-country)
            require_arg "$@"
            OCE_C="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl not found in PATH" >&2
    exit 1
fi

if [[ ! "$DAYS" =~ ^[0-9]+$ ]] || [[ "$DAYS" -lt 1 ]]; then
    echo "--days must be a positive integer" >&2
    exit 2
fi

if [[ -z "$OCE_OU" ]]; then OCE_OU="$CA_OU"; fi
if [[ -z "$OCE_O" ]]; then OCE_O="$CA_O"; fi
if [[ -z "$OCE_C" ]]; then OCE_C="$CA_C"; fi

if [[ -e "$OUT_DIR" ]]; then
    if [[ "$FORCE" -ne 1 ]]; then
        echo "Output path already exists: $OUT_DIR (use --force to overwrite)" >&2
        exit 1
    fi
    rm -rf "$OUT_DIR"
fi

umask 077
mkdir -p "$OUT_DIR"

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CA_SUBJ="/CN=${CA_CN}/OU=${CA_OU}/O=${CA_O}/C=${CA_C}"
OCE_SUBJ="/CN=${OCE_CN}/OU=${OCE_OU}/O=${OCE_O}/C=${OCE_C}"

CA_KEY_PEM="${OUT_DIR}/SK.CA-KLOC.ECDSA.pem"
CA_PUB_PEM="${OUT_DIR}/PK.CA-KLOC.ECDSA.pem"
CA_CERT_PEM="${OUT_DIR}/CERT.CA-KLOC.ECDSA.pem"
CA_CERT_DER="${OUT_DIR}/CERT.CA-KLOC.ECDSA.der"
CA_SERIAL="${OUT_DIR}/CERT.CA-KLOC.ECDSA.srl"
CA_ID_HEX_FILE="${OUT_DIR}/CA-KLOC.ID.hex"

OCE_KEY_PEM="${OUT_DIR}/SK.OCE.ECKA.pem"
OCE_PUB_PEM="${OUT_DIR}/PK.OCE.ECKA.pem"
OCE_CERT_PEM="${OUT_DIR}/CERT.OCE.ECKA.pem"
OCE_CERT_DER="${OUT_DIR}/CERT.OCE.ECKA.der"
OCE_CHAIN_PEM="${OUT_DIR}/CERT.OCE.ECKA.CHAIN.pem"
OCE_CHAIN_DER="${OUT_DIR}/CERT.OCE.ECKA.CHAIN.der"

cat >"${TMP_DIR}/ca.ext.cnf" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

cat >"${TMP_DIR}/oce.ext.cnf" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$CA_KEY_PEM"
openssl pkey -in "$CA_KEY_PEM" -pubout -out "$CA_PUB_PEM"

openssl req -new -sha256 -key "$CA_KEY_PEM" -subj "$CA_SUBJ" -out "${TMP_DIR}/ca.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/ca.csr.pem" \
    -signkey "$CA_KEY_PEM" \
    -extfile "${TMP_DIR}/ca.ext.cnf" \
    -out "$CA_CERT_PEM"

openssl x509 -in "$CA_CERT_PEM" -outform DER -out "$CA_CERT_DER"

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$OCE_KEY_PEM"
openssl pkey -in "$OCE_KEY_PEM" -pubout -out "$OCE_PUB_PEM"

openssl req -new -sha256 -key "$OCE_KEY_PEM" -subj "$OCE_SUBJ" -out "${TMP_DIR}/oce.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/oce.csr.pem" \
    -CA "$CA_CERT_PEM" \
    -CAkey "$CA_KEY_PEM" \
    -CAcreateserial \
    -CAserial "$CA_SERIAL" \
    -extfile "${TMP_DIR}/oce.ext.cnf" \
    -out "$OCE_CERT_PEM"

openssl x509 -in "$OCE_CERT_PEM" -outform DER -out "$OCE_CERT_DER"

cat "$OCE_CERT_PEM" "$CA_CERT_PEM" > "$OCE_CHAIN_PEM"
cat "$OCE_CERT_DER" "$CA_CERT_DER" > "$OCE_CHAIN_DER"

CA_ID_HEX="$(
    openssl x509 -in "$CA_CERT_PEM" -pubkey -noout \
        | openssl pkey -pubin -outform DER \
        | openssl dgst -sha1 -binary \
        | od -An -vtx1 \
        | tr -d ' \n' \
        | tr '[:lower:]' '[:upper:]'
)"
printf '%s\n' "$CA_ID_HEX" > "$CA_ID_HEX_FILE"

echo "Generated SCP11 OCE + CA material in: $OUT_DIR"
echo "CA-KLOC Identifier (SHA-1/SPKI): $CA_ID_HEX"
