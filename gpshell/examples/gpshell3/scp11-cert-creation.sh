#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Generate SCP11 OCE + card-side SD ECKA material using OpenSSL (NIST P-256, ECDSA/SHA-256).

Outputs (GlobalPlatform naming convention):
  SK.CA-KLOC.ECDSA.pem
  PK.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.der
  SK.CA-KLCC.ECDSA.pem
  PK.CA-KLCC.ECDSA.pem
  CERT.CA-KLCC.ECDSA.pem
  CERT.CA-KLCC.ECDSA.der
  SK.KA-KLOC.ECDSA.pem
  PK.KA-KLOC.ECDSA.pem
  CERT.KA-KLOC.ECDSA.pem
  CERT.KA-KLOC.ECDSA.der
  SK.KA-KLCC.ECDSA.pem
  PK.KA-KLCC.ECDSA.pem
  CERT.KA-KLCC.ECDSA.pem
  CERT.KA-KLCC.ECDSA.der
  SK.OCE.ECKA.pem
  PK.OCE.ECKA.pem
  CERT.OCE.ECKA.pem
  CERT.OCE.ECKA.der
  CERT.OCE.ECKA.CHAIN.pem      (CERT.KA-KLOC.ECDSA + CERT.OCE.ECKA)
  CERT.OCE.ECKA.CHAIN.der      (concatenated DER: KA-KLOC then OCE)
  SK.SD.ECKA.pem
  PK.SD.ECKA.pem
  CERT.SD.ECKA.pem
  CERT.SD.ECKA.der
  CERT.SD.ECKA.CHAIN.pem       (CERT.CA-KLCC.ECDSA + CERT.KA-KLCC.ECDSA + CERT.SD.ECKA)
  CERT.SD.ECKA.CHAIN.der       (concatenated DER: CA-KLCC then KA-KLCC then SD)
  CA-KLOC.ID.hex               (CA Subject Key Identifier)
  CA-KLCC.ID.hex               (CA-KLCC Subject Key Identifier)
  KA-KLOC.ID.hex               (KA Subject Key Identifier)
  KA-KLCC.ID.hex               (KA-KLCC Subject Key Identifier)

Usage:
  scp11-cert-creation.sh [options]

Options:
  -o, --out-dir <dir>      Output directory (default: ./scp11-oce-ca)
  -d, --days <n>           Validity in days (default: 3650 = 10 years)
  -c, --curve <name>       EC curve (default: prime256v1)
  -f, --force              Overwrite output directory if it exists

  --cn <value>             CA subject CN (default: GP CA)
  --ou <value>             CA subject OU (default: GP Trust Network)
  --org <value>            CA subject O  (default: GP)
  --country <value>        CA subject C  (default: UK)

  --ka-cn <value>          KA-KLOC subject CN (default: GP KA-KLOC)
  --ka-ou <value>          KA-KLOC subject OU (default: same as CA OU)
  --ka-org <value>         KA-KLOC subject O  (default: same as CA O)
  --ka-country <value>     KA-KLOC subject C  (default: same as CA C)

  --klcc-cn <value>        CA-KLCC subject CN (default: GP CA-KLCC)
  --klcc-ka-cn <value>     KA-KLCC subject CN (default: GP KA-KLCC)
  --sd-cn <value>          SD ECKA subject CN (default: GP SD)

  --oce-cn <value>         OCE subject CN (default: GP OCE)
  --oce-ou <value>         OCE subject OU (default: same as CA OU)
  --oce-org <value>        OCE subject O  (default: same as CA O)
  --oce-country <value>    OCE subject C  (default: same as CA C)

  -h, --help               Show this help

Examples:
  scp11-cert-creation.sh
  scp11-cert-creation.sh -o out/scp11 --cn "My GP CA" --oce-cn "My OCE"
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

KA_CN="GP KA-KLOC"
KA_OU=""
KA_O=""
KA_C=""

KLCC_CA_CN="GP CA-KLCC"
KLCC_KA_CN="GP KA-KLCC"
SD_CN="GP SD"

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
        --ka-cn)
            require_arg "$@"
            KA_CN="$2"
            shift 2
            ;;
        --ka-ou)
            require_arg "$@"
            KA_OU="$2"
            shift 2
            ;;
        --ka-org)
            require_arg "$@"
            KA_O="$2"
            shift 2
            ;;
        --ka-country)
            require_arg "$@"
            KA_C="$2"
            shift 2
            ;;
        --klcc-cn)
            require_arg "$@"
            KLCC_CA_CN="$2"
            shift 2
            ;;
        --klcc-ka-cn)
            require_arg "$@"
            KLCC_KA_CN="$2"
            shift 2
            ;;
        --sd-cn)
            require_arg "$@"
            SD_CN="$2"
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

if [[ -z "$KA_OU" ]]; then KA_OU="$CA_OU"; fi
if [[ -z "$KA_O" ]]; then KA_O="$CA_O"; fi
if [[ -z "$KA_C" ]]; then KA_C="$CA_C"; fi
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
KA_SUBJ="/CN=${KA_CN}/OU=${KA_OU}/O=${KA_O}/C=${KA_C}"
KLCC_CA_SUBJ="/CN=${KLCC_CA_CN}/OU=${CA_OU}/O=${CA_O}/C=${CA_C}"
KLCC_KA_SUBJ="/CN=${KLCC_KA_CN}/OU=${KA_OU}/O=${KA_O}/C=${KA_C}"
OCE_SUBJ="/CN=${OCE_CN}/OU=${OCE_OU}/O=${OCE_O}/C=${OCE_C}"
SD_SUBJ="/CN=${SD_CN}/OU=${OCE_OU}/O=${OCE_O}/C=${OCE_C}"

CA_KEY_PEM="${OUT_DIR}/SK.CA-KLOC.ECDSA.pem"
CA_PUB_PEM="${OUT_DIR}/PK.CA-KLOC.ECDSA.pem"
CA_CERT_PEM="${OUT_DIR}/CERT.CA-KLOC.ECDSA.pem"
CA_CERT_DER="${OUT_DIR}/CERT.CA-KLOC.ECDSA.der"
CA_SERIAL="${OUT_DIR}/CERT.CA-KLOC.ECDSA.srl"
CA_ID_HEX_FILE="${OUT_DIR}/CA-KLOC.ID.hex"

KLCC_CA_KEY_PEM="${OUT_DIR}/SK.CA-KLCC.ECDSA.pem"
KLCC_CA_PUB_PEM="${OUT_DIR}/PK.CA-KLCC.ECDSA.pem"
KLCC_CA_CERT_PEM="${OUT_DIR}/CERT.CA-KLCC.ECDSA.pem"
KLCC_CA_CERT_DER="${OUT_DIR}/CERT.CA-KLCC.ECDSA.der"
KLCC_CA_SERIAL="${OUT_DIR}/CERT.CA-KLCC.ECDSA.srl"
KLCC_CA_ID_HEX_FILE="${OUT_DIR}/CA-KLCC.ID.hex"

KA_KEY_PEM="${OUT_DIR}/SK.KA-KLOC.ECDSA.pem"
KA_PUB_PEM="${OUT_DIR}/PK.KA-KLOC.ECDSA.pem"
KA_CERT_PEM="${OUT_DIR}/CERT.KA-KLOC.ECDSA.pem"
KA_CERT_DER="${OUT_DIR}/CERT.KA-KLOC.ECDSA.der"
KA_SERIAL="${OUT_DIR}/CERT.KA-KLOC.ECDSA.srl"
KA_ID_HEX_FILE="${OUT_DIR}/KA-KLOC.ID.hex"

KLCC_KA_KEY_PEM="${OUT_DIR}/SK.KA-KLCC.ECDSA.pem"
KLCC_KA_PUB_PEM="${OUT_DIR}/PK.KA-KLCC.ECDSA.pem"
KLCC_KA_CERT_PEM="${OUT_DIR}/CERT.KA-KLCC.ECDSA.pem"
KLCC_KA_CERT_DER="${OUT_DIR}/CERT.KA-KLCC.ECDSA.der"
KLCC_KA_SERIAL="${OUT_DIR}/CERT.KA-KLCC.ECDSA.srl"
KLCC_KA_ID_HEX_FILE="${OUT_DIR}/KA-KLCC.ID.hex"

OCE_KEY_PEM="${OUT_DIR}/SK.OCE.ECKA.pem"
OCE_PUB_PEM="${OUT_DIR}/PK.OCE.ECKA.pem"
OCE_CERT_PEM="${OUT_DIR}/CERT.OCE.ECKA.pem"
OCE_CERT_DER="${OUT_DIR}/CERT.OCE.ECKA.der"
OCE_CHAIN_PEM="${OUT_DIR}/CERT.OCE.ECKA.CHAIN.pem"
OCE_CHAIN_DER="${OUT_DIR}/CERT.OCE.ECKA.CHAIN.der"

SD_KEY_PEM="${OUT_DIR}/SK.SD.ECKA.pem"
SD_PUB_PEM="${OUT_DIR}/PK.SD.ECKA.pem"
SD_CERT_PEM="${OUT_DIR}/CERT.SD.ECKA.pem"
SD_CERT_DER="${OUT_DIR}/CERT.SD.ECKA.der"
SD_CHAIN_PEM="${OUT_DIR}/CERT.SD.ECKA.CHAIN.pem"
SD_CHAIN_DER="${OUT_DIR}/CERT.SD.ECKA.CHAIN.der"

cat >"${TMP_DIR}/ca.ext.cnf" <<'EOF'
# GP SCP11 Amendment F Table 6-5: CERT.CA-KLOC.ECDSA.
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.20,1.2.840.114283.100.0.10.2.1.20,1.2.840.114283.100.0.10.2.1.0
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

cat >"${TMP_DIR}/ca-klcc.ext.cnf" <<'EOF'
# GP SCP11 Amendment F Table 6-5: CERT.CA-KLCC.ECDSA.
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.30,1.2.840.114283.100.0.10.2.1.30,1.2.840.114283.100.0.10.2.1.0
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

cat >"${TMP_DIR}/ka.ext.cnf" <<'EOF'
# GP SCP11 Amendment F Table 6-6: CERT.KA-KLOC.ECDSA.
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign
authorityKeyIdentifier=keyid,issuer
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.40,1.2.840.114283.100.0.10.2.1.40,1.2.840.114283.100.0.10.2.1.0
subjectKeyIdentifier=hash
EOF

cat >"${TMP_DIR}/ka-klcc.ext.cnf" <<'EOF'
# GP SCP11 Amendment F Table 6-6: CERT.KA-KLCC.ECDSA.
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign
authorityKeyIdentifier=keyid,issuer
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.50,1.2.840.114283.100.0.10.2.1.50,1.2.840.114283.100.0.10.2.1.0
subjectKeyIdentifier=hash
EOF

cat >"${TMP_DIR}/oce.ext.cnf" <<'EOF'
# GP SCP11 Amendment F Table 6-7: CERT.OCE.ECKA.
keyUsage=critical,keyAgreement
authorityKeyIdentifier=keyid,issuer
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.0,1.2.840.114283.100.0.10.2.1.0
subjectKeyIdentifier=hash
EOF

cat >"${TMP_DIR}/sd.ext.cnf" <<'EOF'
# GP SCP11 SD ECKA certificate.
keyUsage=critical,keyAgreement
authorityKeyIdentifier=keyid,issuer
certificatePolicies=critical,1.2.840.114283.100.0.1.2.1.10,1.2.840.114283.100.0.10.2.1.10
subjectKeyIdentifier=hash
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

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$KLCC_CA_KEY_PEM"
openssl pkey -in "$KLCC_CA_KEY_PEM" -pubout -out "$KLCC_CA_PUB_PEM"

openssl req -new -sha256 -key "$KLCC_CA_KEY_PEM" -subj "$KLCC_CA_SUBJ" -out "${TMP_DIR}/ca-klcc.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/ca-klcc.csr.pem" \
    -signkey "$KLCC_CA_KEY_PEM" \
    -extfile "${TMP_DIR}/ca-klcc.ext.cnf" \
    -out "$KLCC_CA_CERT_PEM"

openssl x509 -in "$KLCC_CA_CERT_PEM" -outform DER -out "$KLCC_CA_CERT_DER"

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$KA_KEY_PEM"
openssl pkey -in "$KA_KEY_PEM" -pubout -out "$KA_PUB_PEM"

openssl req -new -sha256 -key "$KA_KEY_PEM" -subj "$KA_SUBJ" -out "${TMP_DIR}/ka.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/ka.csr.pem" \
    -CA "$CA_CERT_PEM" \
    -CAkey "$CA_KEY_PEM" \
    -CAcreateserial \
    -CAserial "$CA_SERIAL" \
    -extfile "${TMP_DIR}/ka.ext.cnf" \
    -out "$KA_CERT_PEM"

openssl x509 -in "$KA_CERT_PEM" -outform DER -out "$KA_CERT_DER"

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$KLCC_KA_KEY_PEM"
openssl pkey -in "$KLCC_KA_KEY_PEM" -pubout -out "$KLCC_KA_PUB_PEM"

openssl req -new -sha256 -key "$KLCC_KA_KEY_PEM" -subj "$KLCC_KA_SUBJ" -out "${TMP_DIR}/ka-klcc.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/ka-klcc.csr.pem" \
    -CA "$KLCC_CA_CERT_PEM" \
    -CAkey "$KLCC_CA_KEY_PEM" \
    -CAcreateserial \
    -CAserial "$KLCC_CA_SERIAL" \
    -extfile "${TMP_DIR}/ka-klcc.ext.cnf" \
    -out "$KLCC_KA_CERT_PEM"

openssl x509 -in "$KLCC_KA_CERT_PEM" -outform DER -out "$KLCC_KA_CERT_DER"

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$OCE_KEY_PEM"
openssl pkey -in "$OCE_KEY_PEM" -pubout -out "$OCE_PUB_PEM"

openssl req -new -sha256 -key "$OCE_KEY_PEM" -subj "$OCE_SUBJ" -out "${TMP_DIR}/oce.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/oce.csr.pem" \
    -CA "$KA_CERT_PEM" \
    -CAkey "$KA_KEY_PEM" \
    -CAcreateserial \
    -CAserial "$KA_SERIAL" \
    -extfile "${TMP_DIR}/oce.ext.cnf" \
    -out "$OCE_CERT_PEM"

openssl x509 -in "$OCE_CERT_PEM" -outform DER -out "$OCE_CERT_DER"

cat "$KA_CERT_PEM" "$OCE_CERT_PEM" > "$OCE_CHAIN_PEM"
cat "$KA_CERT_DER" "$OCE_CERT_DER" > "$OCE_CHAIN_DER"

openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$SD_KEY_PEM"
openssl pkey -in "$SD_KEY_PEM" -pubout -out "$SD_PUB_PEM"

openssl req -new -sha256 -key "$SD_KEY_PEM" -subj "$SD_SUBJ" -out "${TMP_DIR}/sd.csr.pem"
openssl x509 -req -sha256 -days "$DAYS" \
    -in "${TMP_DIR}/sd.csr.pem" \
    -CA "$KLCC_KA_CERT_PEM" \
    -CAkey "$KLCC_KA_KEY_PEM" \
    -CAcreateserial \
    -CAserial "$KLCC_KA_SERIAL" \
    -extfile "${TMP_DIR}/sd.ext.cnf" \
    -out "$SD_CERT_PEM"

openssl x509 -in "$SD_CERT_PEM" -outform DER -out "$SD_CERT_DER"

cat "$KLCC_CA_CERT_PEM" "$KLCC_KA_CERT_PEM" "$SD_CERT_PEM" > "$SD_CHAIN_PEM"
cat "$KLCC_CA_CERT_DER" "$KLCC_KA_CERT_DER" "$SD_CERT_DER" > "$SD_CHAIN_DER"

CA_ID_HEX="$(
    openssl x509 -in "$CA_CERT_PEM" -noout -ext subjectKeyIdentifier \
        | awk '
            /Subject Key Identifier/ { getline; gsub(/[^0-9A-Fa-f]/, "", $0); print toupper($0); exit }
        '
)"
if [[ -z "$CA_ID_HEX" ]]; then
    echo "Failed to extract CA Subject Key Identifier from $CA_CERT_PEM" >&2
    exit 1
fi
printf '%s\n' "$CA_ID_HEX" > "$CA_ID_HEX_FILE"

KLCC_CA_ID_HEX="$(
    openssl x509 -in "$KLCC_CA_CERT_PEM" -noout -ext subjectKeyIdentifier \
        | awk '
            /Subject Key Identifier/ { getline; gsub(/[^0-9A-Fa-f]/, "", $0); print toupper($0); exit }
        '
)"
if [[ -z "$KLCC_CA_ID_HEX" ]]; then
    echo "Failed to extract CA-KLCC Subject Key Identifier from $KLCC_CA_CERT_PEM" >&2
    exit 1
fi
printf '%s\n' "$KLCC_CA_ID_HEX" > "$KLCC_CA_ID_HEX_FILE"

KA_ID_HEX="$(
    openssl x509 -in "$KA_CERT_PEM" -noout -ext subjectKeyIdentifier \
        | awk '
            /Subject Key Identifier/ { getline; gsub(/[^0-9A-Fa-f]/, "", $0); print toupper($0); exit }
        '
)"
if [[ -z "$KA_ID_HEX" ]]; then
    echo "Failed to extract KA Subject Key Identifier from $KA_CERT_PEM" >&2
    exit 1
fi
printf '%s\n' "$KA_ID_HEX" > "$KA_ID_HEX_FILE"

KLCC_KA_ID_HEX="$(
    openssl x509 -in "$KLCC_KA_CERT_PEM" -noout -ext subjectKeyIdentifier \
        | awk '
            /Subject Key Identifier/ { getline; gsub(/[^0-9A-Fa-f]/, "", $0); print toupper($0); exit }
        '
)"
if [[ -z "$KLCC_KA_ID_HEX" ]]; then
    echo "Failed to extract KA-KLCC Subject Key Identifier from $KLCC_KA_CERT_PEM" >&2
    exit 1
fi
printf '%s\n' "$KLCC_KA_ID_HEX" > "$KLCC_KA_ID_HEX_FILE"

echo "Generated SCP11 OCE + SD ECKA material in: $OUT_DIR"
echo "CA-KLOC Identifier (Subject Key Identifier): $CA_ID_HEX"
echo "CA-KLCC Identifier (Subject Key Identifier): $KLCC_CA_ID_HEX"
echo "KA-KLOC Identifier (Subject Key Identifier): $KA_ID_HEX"
echo "KA-KLCC Identifier (Subject Key Identifier): $KLCC_KA_ID_HEX"
