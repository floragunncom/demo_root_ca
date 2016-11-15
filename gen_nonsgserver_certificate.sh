#!/bin/bash
set -e
ORGA_NAME="$1"
SERVER_NAME="$2"
SERVER_DNS="$3"
FILENAME="$4"

echo "Orga: $ORGA_NAME"
echo "Subject: $SERVER_NAME"
echo "Dns: $SERVER_DNS"
echo "Filename: $FILENAME"

if [ -z "$5" ] ; then
  unset CA_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
 else
  CA_PASS="$5"
fi

openssl genrsa -des3 -out $FILENAME.key -passout pass:tmpkeypass 1024
openssl req -new -key $FILENAME.key -out $FILENAME.csr -passin pass:tmpkeypass \
   -subj "$SERVER_NAME" \
   -reqexts SAN \
   -config <(cat /etc/ssl/openssl.cnf \
     <(printf "[SAN]\nsubjectAltName=DNS:$SERVER_DNS"))

cp $FILENAME.key $FILENAME.key.org
openssl rsa -in $FILENAME.key.org -out $FILENAME.key -passin pass:tmpkeypass

openssl ca \
    -in "$FILENAME.csr" \
    -notext \
    -out "$FILENAME-signed.pem" \
    -config "etc/gen-signing-ca.conf.$ORGA_NAME" \
    -extensions v3_req \
    -batch \
    -passin "pass:$CA_PASS" \
    -days 720 \
    -extensions server_ext

cat "$FILENAME-signed.pem" ca/chain-ca.pem  > $FILENAME.crt.pem