#!/bin/bash
#./gen_root.sh <organisation name> <root ca passsord> <truststore password>

printerr() {
  if [ $? != 0 ]; then
      echo "-- ERROR!! --"
  fi 
  
}
trap printerr 0

set -e
rm -rf ca certs* crl *.jks
rm -rf ca crl truststore.* certs 
rm -rf etc/gen-* || true
echo "" > gen_root.log

ORGA_NAME="$1"

if [ -z "$2" ] ; then
  unset CA_PASS TS_PASS
  read -p "Enter CA pass: " -s CA_PASS ; echo
  read -p "Enter Truststore pass: " -s TS_PASS ; echo
 else
  CA_PASS="$2"
  TS_PASS="$3"
fi

sed -e "s/_RPLC_ORG_NAME/$ORGA_NAME/g" "etc/root-ca.conf" > "etc/gen-root-ca.conf.$ORGA_NAME"
sed -e "s/_RPLC_ORG_NAME/$ORGA_NAME/g" "etc/signing-ca.conf" > "etc/gen-signing-ca.conf.$ORGA_NAME"


mkdir -p ca/root-ca/private ca/root-ca/db
chmod 700 ca/root-ca/private

cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

#Create a root key
echo "Create root key"
openssl ecparam -name secp384r1 -genkey | openssl ec -aes-256-cbc -out ca/root-ca/private/root-ca.key -passout "pass:$CA_PASS" >> gen_root.log  2>&1

openssl req -new -x509 \
    -config "etc/gen-root-ca.conf.$ORGA_NAME" \
    -out ca/root-ca.pem \
    -key ca/root-ca/private/root-ca.key \
	-batch \
	-extensions root_ca_ext \
	-passin "pass:$CA_PASS"  >> gen_root.log  2>&1

openssl x509 -noout -text -in ca/root-ca.pem  >> gen_root.log 2>&1
	
echo Root CA generated
	
mkdir -p ca/signing-ca/private ca/signing-ca/db
chmod 700 ca/signing-ca/private

cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl

echo "Create signing key"
openssl ecparam -name secp384r1 -genkey | openssl ec -aes-256-cbc -out ca/signing-ca/private/signing-ca.key -passout "pass:$CA_PASS"  >> gen_root.log  2>&1

echo "Create intermediate certificate signing request (CSR)"
openssl req -new \
    -config "etc/gen-signing-ca.conf.$ORGA_NAME" \
    -out ca/signing-ca.csr \
    -key ca/signing-ca/private/signing-ca.key \
	-batch \
	-passin "pass:$CA_PASS"  >> gen_root.log  2>&1

openssl ca \
    -config "etc/gen-root-ca.conf.$ORGA_NAME" \
    -in ca/signing-ca.csr \
    -out ca/signing-ca.pem \
    -extensions signing_ca_ext \
    -notext \
	-batch \
	-passin "pass:$CA_PASS"  >> gen_root.log 2>&1

echo "Verify intermediate ca"

cat ca/signing-ca.pem
openssl verify -CAfile ca/root-ca.pem ca/signing-ca.pem
openssl x509 -noout -text -in ca/signing-ca.pem >> gen_root.log
	
echo Signing CA generated
cat ca/signing-ca.pem ca/root-ca.pem > ca/chain-ca.pem

#http://stackoverflow.com/questions/652916/converting-a-java-keystore-into-pem-format

keytool \
    -import \
    -v \
    -keystore truststore.jks   \
    -storepass "$TS_PASS"  \
    -noprompt -alias root-ca-chain \
    -file ca/root-ca.pem >> gen_root.log  2>&1
    
echo JKS truststore generated

keytool -importkeystore -srckeystore "truststore.jks" -srcstorepass "$TS_PASS" -srcstoretype JKS -deststoretype PKCS12 -deststorepass "$TS_PASS" -destkeystore "truststore.p12" >> gen_root.log  2>&1

echo PKCS12 truststore generated
echo "All successful"
