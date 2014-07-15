#! /bin/bash

#move the custom cnf into our working directory
echo ""
echo "IF SOME ERROR OCCURS: go to renewcerts directory"
echo "edit the cyassl_global.cnf file line 45, make sure"
echo "line 45 is the cyassl directory you are currently working out of."
echo ""
cp renewcerts/cyassl.cnf cyassl.cnf

# To generate these all in sha1 add the flag "-sha1" on appropriate lines
# That is all lines beginning with:  "openssl req"

############################################################
########## update the self-signed client-cert.pem ##########
############################################################
echo ""
echo "Updating client-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e "US\nMontana\nBozeman\nwolfSSL\nProgramming\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key client-key.pem -nodes -out client-cert.csr


openssl x509 -req -in client-cert.csr -days 1000 -extfile cyassl.cnf -extensions cyassl_opts -signkey client-key.pem -out client-cert.pem
rm client-cert.csr

openssl x509 -in client-cert.pem -text > tmp.pem
mv tmp.pem client-cert.pem
############################################################
########## update the self-signed ca-cert.pem ##############
############################################################
echo ""
echo "Updating ca-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e  "US\nMontana\nBozeman\nSawtooth\nConsulting\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ca-key.pem -nodes -out ca-cert.csr


openssl x509 -req -in ca-cert.csr -days 1000 -extfile cyassl.cnf -extensions cyassl_opts -signkey ca-key.pem -out ca-cert.pem
rm ca-cert.csr

openssl x509 -in ca-cert.pem -text > tmp.pem
mv tmp.pem ca-cert.pem
###########################################################
########## update and sign server-cert.ptm ################
###########################################################
echo ""
echo "Updating server-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e "US\nMontana\nBozeman\nwolfSSL\nSupport\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key server-key.pem -nodes > server-req.pem

openssl x509 -req -in server-req.pem -extfile cyassl.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem

rm server-req.pem

openssl x509 -in ca-cert.pem -text > ca_tmp.pem
openssl x509 -in server-cert.pem -text > srv_tmp.pem
mv srv_tmp.pem server-cert.pem
############################################################
########## update and sign the server-ecc-rsa.pem ##########
############################################################
echo ""
echo "Updating server-ecc-rsa.pem"
echo ""
echo -e "US\nMontana\nBozeman\nElliptic - RSAsig\nECC-RSAsig\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ecc-key.pem -nodes > server-ecc-req.pem

openssl x509 -req -in server-ecc-req.pem -extfile cyassl.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-ecc-rsa.pem

rm server-ecc-req.pem

openssl x509 -in server-ecc-rsa.pem -text > tmp.pem
mv tmp.pem server-ecc-rsa.pem

############################################################
########## make .der files from .pem files #################
############################################################
echo ""
echo "Generating new ca-cert.der, client-cert.der, server-cert.der..."
echo ""
openssl x509 -inform PEM -in ca-cert.pem -outform DER -out ca-cert.der
openssl x509 -inform PEM -in client-cert.pem -outform DER -out client-cert.der
openssl x509 -inform PEM -in server-cert.pem -outform DER -out server-cert.der
echo "Changing directory to cyassl root..."
echo ""
cd ../
echo "Execute ./gencertbuf.pl..."
echo ""
./gencertbuf.pl
echo "Change directory back to cyassl/certs"
echo ""
cd certs
echo "We are back in the certs directory."
echo ""
############################################################
########## update the ca signed ntru-cert.pem ##############
############################################################

########## NOT YET COMPLETE, WILL PUSH WHEN READY. #########

############################################################
########## generate the new crls ###########################
############################################################

#set up the file system for updating the crls
touch crl/index.txt
touch crl/blank.index.txt
mkdir crl/demoCA
touch crl/demoCA/index.txt

echo "Updating the crls..."
cd crl
echo "changed directory: cd/crl"
./gencrls.sh
echo "ran ./gencrls.sh"

#cleanup the file system now that we're done
echo ""
echo "Performing final steps, cleaning up the file system..."

rm ../cyassl.cnf
rm blank.index.txt
rm index.*
rm crlnumber.old
rm -r demoCA
echo "Removed ../cyassl.cnf, blank.index.txt, index.*, crlnumber.old, demoCA/"
echo ""

cd ../
echo "changed directory: cd ../"

echo ""
echo "IF SOME ERROR OCCURS: go to renewcerts directory"
echo "edit the cyassl_global.cnf file line 45, make sure"
echo "line 45 is the cyassl directory you are currently working out of."
echo ""
echo "You will need to manually copy ca_tmp.pem and paste it into server-cert.pem."
echo "BELOW the text body of server-cert.pem! If you paste it above the server"
echo "text body, the certificate chain will not be recognized properly."
echo ""
