#! /bin/bash

#move the custom cnf into our working directory
cp renewcerts/cyassl_custom.cnf cyassl_custom.cnf

# To generate these all in sha1 add the flag "-sha1" on appropriate lines
# That is all lines beginning with:  "openssl req"

############################################################
########## update the self-signed client-cert.pem ##########
############################################################
echo "Updating client-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e "US\nMontana\nBozeman\nwolfSSL\nProgramming\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key client-key.pem -nodes -out client-cert.csr


openssl x509 -req -in client-cert.csr -days 1000 -extfile cyassl_custom.cnf -extensions cyassl_opts -signkey client-key.pem -out client-cert.pem
rm client-cert.csr

openssl x509 -in client-cert.pem -text > tmp.pem
mv tmp.pem client-cert.pem
############################################################
########## update the self-signed ca-cert.pem ##############
############################################################
echo "Updating ca-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e  "US\nMontana\nBozeman\nSawtooth\nConsulting\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ca-key.pem -nodes -out ca-cert.csr


openssl x509 -req -in ca-cert.csr -days 1000 -extfile cyassl_custom.cnf -extensions cyassl_opts -signkey ca-key.pem -out ca-cert.pem
rm ca-cert.csr

openssl x509 -in ca-cert.pem -text > tmp.pem
mv tmp.pem ca-cert.pem
###########################################################
########## update and sign server-cert.ptm ################
###########################################################
echo "Updating server-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e "US\nMontana\nBozeman\nwolfSSL\nSupport\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key server-key.pem -nodes > server-req.pem

openssl x509 -req -in server-req.pem -extfile cyassl_custom.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem

rm server-req.pem

openssl x509 -in ca-cert.pem -text > ca_tmp.pem
openssl x509 -in server-cert.pem -text > srv_tmp.pem
mv srv_tmp.pem server-cert.pem
cat ca_tmp.pem >> server-cert.pem
rm ca_tmp.pem
############################################################
########## update and sign the server-ecc-rsa.pem ##########
############################################################
echo "Updating server-ecc-rsa.pem"
echo ""
echo -e "US\nMontana\nBozeman\nElliptic - RSAsig\nECC-RSAsig\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ecc-key.pem -nodes > server-ecc-req.pem

openssl x509 -req -in server-ecc-req.pem -extfile cyassl_custom.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-ecc-rsa.pem

rm server-ecc-req.pem

openssl x509 -in server-ecc-rsa.pem -text > tmp.pem
mv tmp.pem server-ecc-rsa.pem

############################################################
########## make .der files from .pem files #################
############################################################
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
############################################################
########## generate the new crls ###########################
############################################################

echo "Change directory to cyassl/certs"
echo ""
cd certs
echo "We are back in the certs directory"
echo ""

#set up the file system for updating the crls
echo "setting up the file system for generating the crls..."
echo ""
touch crl/index.txt
touch crl/crlnumber
echo "01" >> crl/crlnumber
touch crl/blank.index.txt
mkdir crl/demoCA
touch crl/demoCA/index.txt

echo "Updating the crls..."
echo ""
cd crl
echo "changed directory: cd/crl"
echo ""
./gencrls.sh
echo "ran ./gencrls.sh"
echo ""

#cleanup the file system now that we're done
echo "Performing final steps, cleaning up the file system..."
echo ""

rm ../cyassl_custom.cnf
rm blank.index.txt
rm index.*
rm crlnumber*
rm -r demoCA
echo "Removed ../cyassl_custom.cnf, blank.index.txt, index.*, crlnumber*, demoCA/"
echo ""

cd ../../
echo "changed directory to cyassl root directory."
echo ""

############################################################
########## update the ntru-cert.pem & ntru-key.pem #########
############################################################
# check options.h for HAVE_NTRU defined

# if DEFINED
if grep HAVE_NTRU "cyassl/options.h"
then
    echo "HAVE_NTRU, good to procede."
    echo ""
else
    # Save the users configure state
    echo "Saving the configure state"
    echo ""
    cp config.status tmp.status
    cp cyassl/options.h tmp.options.h

    # run make clean
    echo "Running make clean"
    echo ""
    make clean
    # Configure with ntru, enable certgen and keygen
    echo "Configuring with ntru, enabling certgen and keygen"
    echo ""
    ./configure --with-ntru --enable-certgen --enable-keygen
    # run make check
    make check

    # check options.h a second time, if the user had
    # ntru installed on their system and in the default
    # path location, then it will now be defined, if the 
    # user does not have ntru on their system this will fail
    # again and we will not update the ntru-cert and ntru-key

    # if NOW_DEFINED 
    if grep HAVE_NTRU "cyassl/options.h"
    then
        # copy/paste ntru-cert to certs/
        mv ntru-cert.pem certs/ntru-cert.pem
        # copy/paste ntru-key to certs/
        mv ntru-key.raw certs/ntru-key.raw
                                              
        # restore previous configure state
        mv tmp.status config.status
        mv tmp.options.h cyassl/options.h
        make clean
        make -j 8
    else
        # restore previous configure state
        mv tmp.status config.status
        mv tmp.options.h cyassl/options.h
        make clean
        make -j 8
        echo ""
        echo "User does not have ntru installed at the default location,"
        echo "or the user does not have ntru installed, ntru-cert.pem and"
        echo "ntru-key.raw were not updated."
        echo "Please check your ntru install location."
        echo "Run ./configure --with-ntru=<install_path_here> --enable-certgen --enable-keygen"
        echo "Then execute this script again to update the ntru cert and key."
        echo ""
    fi #END NOW_DEFINED
fi #END DEFINED

