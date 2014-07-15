#!/bin/bash

# gencrls, crl config already done, see taoCerts.txt for setup



# caCrl
openssl ca -config ../renewcerts/cyassl_global.cnf -gencrl -crldays 365 -out crl.pem -keyfile $PWD/../ca-key.pem -cert $PWD/../ca-cert.pem

# metadata
openssl crl -in crl.pem -text > tmp
mv tmp crl.pem
# install (only needed if working outside cyassl)
#cp crl.pem ~/cyassl/certs/crl/crl.pem

# caCrl server revoked
openssl ca -config ../renewcerts/cyassl_global.cnf -revoke $PWD/../server-cert.pem -keyfile $PWD/../ca-key.pem -cert $PWD/../ca-cert.pem

# caCrl server revoked generation
openssl ca -config ../renewcerts/cyassl_global.cnf -gencrl -crldays 365 -out crl.revoked -keyfile $PWD/../ca-key.pem -cert $PWD/../ca-cert.pem

# metadata
openssl crl -in crl.revoked -text > tmp
mv tmp crl.revoked
# install (only needed if working outside cyassl)
#cp crl.revoked ~/cyassl/certs/crl/crl.revoked

# remove revoked so next time through the normal CA won't have server revoked
cp blank.index.txt demoCA/index.txt

# cliCrl
openssl ca -config ../renewcerts/cyassl_global.cnf -gencrl -crldays 365 -out cliCrl.pem -keyfile $PWD/../client-key.pem -cert $PWD/../client-cert.pem

# metadata
openssl crl -in cliCrl.pem -text > tmp
mv tmp cliCrl.pem
# install (only needed if working outside cyassl)
#cp cliCrl.pem ~/cyassl/certs/crl/cliCrl.pem

# eccCliCRL
openssl ca -config ../renewcerts/cyassl_global.cnf -gencrl -crldays 365 -out eccCliCRL.pem -keyfile $PWD/../ecc-client-key.pem -cert $PWD/../client-ecc-cert.pem

# metadata
openssl crl -in eccCliCRL.pem -text > tmp
mv tmp eccCliCRL.pem
# install (only needed if working outside cyassl)
#cp eccCliCRL.pem ~/cyassl/certs/crl/eccCliCRL.pem

# eccSrvCRL
openssl ca -config ../renewcerts/cyassl_global.cnf -gencrl -crldays 365 -out eccSrvCRL.pem -keyfile $PWD/../ecc-key.pem -cert $PWD/../server-ecc.pem

# metadata
openssl crl -in eccSrvCRL.pem -text > tmp
mv tmp eccSrvCRL.pem
# install (only needed if working outside cyassl)
#cp eccSrvCRL.pem ~/cyassl/certs/crl/eccSrvCRL.pem

