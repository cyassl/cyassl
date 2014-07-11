#!/bin/bash

# gencrls, crl config already done, see taoCerts.txt for setup



######## caCrl ######## 
openssl ca -gencrl -crldays 365 -out crl.pem -keyfile ~/work/my_cyassl_git/certs/ca-key.pem -cert ~/work/my_cyassl_git/certs/ca-cert.pem

            ## metadata ##
openssl crl -in crl.pem -text > tmp
mv tmp crl.pem
            ## install ##
cp crl.pem ~/work/my_cyassl_git/certs/crl/crl.pem


######## caCrl server revoked ########
openssl ca -revoke ~/work/my_cyassl_git/certs/server-cert.pem -keyfile ~/work/my_cyassl_git/certs/ca-key.pem -cert ~/work/my_cyassl_git/certs/ca-cert.pem


######## caCrl server revoked generation ########
openssl ca -gencrl -crldays 365 -out crl.revoked -keyfile ~/work/my_cyassl_git/certs/ca-key.pem -cert ~/work/my_cyassl_git/certs/ca-cert.pem

            ## metadata ##
#openssl crl -in crl.revoked -text > tmp
mv tmp crl.revoked
            ## install ##
cp crl.revoked ~/work/my_cyassl_git/certs/crl/crl.revoked

            ## remove revoked so next time through the normal CA won't have server revoked ##
cp blank.index.txt demoCA/index.txt

######## cliCrl ########
openssl ca -gencrl -crldays 365 -out cliCrl.pem -keyfile ~/work/my_cyassl_git/certs/client-key.pem -cert ~/work/my_cyassl_git/certs/client-cert.pem

            ## metadata ##
openssl crl -in cliCrl.pem -text > tmp
mv tmp cliCrl.pem
            ## install ##
cp cliCrl.pem ~/work/my_cyassl_git/certs/crl/cliCrl.pem

####### eccCliCRL ########
openssl ca -gencrl -crldays 365 -out eccCliCRL.pem -keyfile ~/cyassl/certs/ecc-client-key.pem -cert ~/cyassl/certs/client-ecc-cert.pem

            ## metadata ##
openssl crl -in eccCliCRL.pem -text > tmp
mv tmp eccCliCRL.pem
            ## install ##
cp eccCliCRL.pem ~/cyassl/certs/crl/eccCliCRL.pem

######## eccSrvCRL ########
openssl ca -gencrl -crldays 365 -out eccSrvCRL.pem -keyfile ~/cyassl/certs/ecc-key.pem -cert ~/cyassl/certs/server-ecc.pem

            ## metadata ##
openssl crl -in eccSrvCRL.pem -text > tmp
mv tmp eccSrvCRL.pem
            ## install ##
cp eccSrvCRL.pem ~/cyassl/certs/crl/eccSrvCRL.pem

