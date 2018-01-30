#!/bin/bash
#https://medium.com/where-the-flamingcow-roams/elliptic-curve-certificate-authority-bbdb9c3855f7
#<organisation name> <clientdn> <filename> <key password> <root ca passsord> 
#"Example Inc." "/CN=es-node.example.com/OU=SSL/O=Test/L=Test/C=DE" "es-node.example.com" "es-node" changeit capass

printerr() {
  if [ $? != 0 ]; then
      echo "-- ERROR!! --"
  fi 
  
}
trap printerr 0



set -e
ORGA_NAME="$1"
CLIENT_NAME="$2"
FILENAME="$3"

rm -rf "$FILENAME.p12"
rm -rf "$FILENAME.csr"
rm -rf "$FILENAME-signed.pem"

echo "Orga: $ORGA_NAME"
echo "Client name: $CLIENT_NAME"

if [ -z "$4" ] ; then
  unset KEY_PASS
  read -p "Enter KEY pass: " -s KEY_PASS ; echo
 else
  KEY_PASS="$4"
fi

if [ -z "$5" ] ; then
  unset CA_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
 else
  CA_PASS="$5"
fi

#https://support.quovadisglobal.com/kb/a471/inserting-custom-oids-into-openssl.aspx
echo "Create cert key"
openssl ecparam -name secp384r1 -genkey | openssl ec -aes-256-cbc -out $FILENAME.key.tmp -passout "pass:$KEY_PASS"
#echo "topk8"
openssl pkcs8 -topk8 -inform pem -in $FILENAME.key.tmp -outform pem -out $FILENAME.key -passout "pass:$KEY_PASS" -passin "pass:$KEY_PASS"
#rm -rf $FILENAME.key.tmp

echo "Create a client certificate signing request (CSR)"
openssl req -new -key "$FILENAME.key" -out "$FILENAME.csr" -passin "pass:$KEY_PASS" \
   -subj "$CLIENT_NAME" 
   #\
   #-config "etc/gen-signing-ca.conf.$ORGA_NAME"

echo Sign certificate request with CA
openssl ca \
    -in "$FILENAME.csr" \
    -notext \
    -out "$FILENAME-signed.pem" \
    -config "etc/gen-signing-ca.conf.$ORGA_NAME" \
    -extensions v3_req \
    -batch \
	-passin "pass:$CA_PASS" \
	-extensions server_ext 
	#TODO client-ext

#echo "Import back to keystore (including CA chain)"

#cat ca/chain-ca.pem "$CLIENT_NAME-signed.pem" | keytool \
#    -importcert \
#    -keystore "$CLIENT_NAME-keystore.jks" \
#    -storepass "$KS_PASS" \
#    -noprompt \
#    -alias "$CLIENT_NAME"

#keytool -importkeystore -srckeystore "$CLIENT_NAME-keystore.jks" -srcstorepass "$KS_PASS" -srcstoretype JKS -deststoretype PKCS12 -deststorepass "$KS_PASS" -destkeystore "$CLIENT_NAME-keystore.p12"

#openssl pkcs12 -in "$FILENAME-keystore.p12" -out "$FILENAME.all.pem" -nodes -passin "pass:$KS_PASS"
#openssl pkcs12 -in "$FILENAME-keystore.p12" -out "$FILENAME.key.pem" -nocerts -nodes -passin "pass:$KS_PASS"
#openssl pkcs12 -in "$FILENAME-keystore.p12" -out "$FILENAME.crt.pem" -clcerts -nokeys -passin "pass:$KS_PASS"

#cat $FILENAME.crt.pem ca/chain-ca.pem  > $FILENAME.crtfull.pem

cat "$FILENAME-signed.pem" ca/signing-ca.pem  > $FILENAME.chain.pem
openssl pkcs12 -export -in "$FILENAME.chain.pem" -inkey "$FILENAME.key" -out "$FILENAME.p12" -passin "pass:$KEY_PASS" -passout "pass:$KEY_PASS"

echo All done for "$CLIENT_NAME"