#!/bin/bash
#<organisation name> <nodedn> <nodedns> <filename> <key password> <root ca passsord> 
#"Example Inc." "/CN=es-node.example.com/OU=SSL/O=Test/L=Test/C=DE" "es-node.example.com" "es-node" changeit capass

printerr() {
  if [ $? != 0 ]; then
      echo "-- ERROR!! --"
  fi 
  
}
trap printerr 0

set -e
ORGA_NAME="$1"
SERVER_NAME="$2"
SERVER_DNS="$3"
FILENAME="$4"

echo "Subject: $SERVER_NAME"
echo "Dns: $SERVER_DNS"
echo "Filename: $FILENAME"

if [ -z "$5" ] ; then
  unset KEY_PASS
  read -p "Enter KEY pass: " -s KEY_PASS ; echo
 else
  KEY_PASS="$5"
fi

if [ -z "$6" ] ; then
  unset CA_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
 else
  CA_PASS="$6"
fi


cat >tmp_openssl.cnf <<EOL

oid_section = OIDs

[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
default_md = sha256 

[req_distinguished_name]
# empty
# set in command line


[ OIDs ]
sgID=1.2.3.4.5.5

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]

EOL

#https://support.quovadisglobal.com/kb/a471/inserting-custom-oids-into-openssl.aspx
echo "Create cert key"
openssl ecparam -name secp384r1 -genkey | openssl ec -aes-256-cbc -out $FILENAME.key.tmp -passout "pass:$KEY_PASS"
#echo "topk8"
openssl pkcs8 -topk8 -inform pem -in $FILENAME.key.tmp -outform pem -out $FILENAME.key -passout "pass:$KEY_PASS" -passin "pass:$KEY_PASS"
#rm -rf $FILENAME.key.tmp

echo "Create a client certificate signing request (CSR)"
openssl req -new -key $FILENAME.key -out $FILENAME.csr -passin "pass:$KEY_PASS" \
   -subj "$SERVER_NAME" \
   -reqexts v3_req \
   -config <(cat tmp_openssl.cnf \
     <(printf "DNS.1=$SERVER_DNS\nRID.1=sgID"))

echo "Sign cert with intermediate key"
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

#we do not add the root certificate to the chain
cat "$FILENAME-signed.pem" ca/signing-ca.pem  > $FILENAME.chain.pem
openssl pkcs12 -export -in "$FILENAME.chain.pem" -inkey "$FILENAME.key" -out "$FILENAME.p12" -passin "pass:$KEY_PASS" -passout "pass:$KEY_PASS"