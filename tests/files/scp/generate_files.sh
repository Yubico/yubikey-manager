#!/usr/bin/env bash
set -euo pipefail

rm -rf build
mkdir build
cd build

config=$(cat <<- EOF
[ ca ]
default_ca               = CA_default

[ CA_default ]
default_days             = 90
default_md               = sha256
preserve                 = no
x509_extensions          = ca_kloc
copy_extensions          = copy
serial                   = serial.txt
database                 = database.txt

[ req ]
distinguished_name       = ca_distinguished_name
x509_extensions          = ca_kloc
string_mask              = utf8only
encrypt_key              = no

[ signing_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ signing_req ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer

[ ca_distinguished_name ]

[ ca_kloc ]
subjectKeyIdentifier     = hash
basicConstraints         = critical,CA:true,pathlen:1
keyUsage                 = critical,cRLSign,keyCertSign
certificatePolicies      = critical,1.2.840.114283.100.0.10.2.1.20,1.2.840.114283.100.0.10.2.1.40,1.2.840.114283.100.0.10.2.1.0

[ ka_kloc ]
basicConstraints         = critical,CA:true,pathlen:0
keyUsage                 = critical,keyCertSign
certificatePolicies      = critical,1.2.840.114283.100.0.10.2.1.40,1.2.840.114283.100.0.10.2.1.0

[ oce ]
keyUsage                 = critical,keyAgreement
certificatePolicies      = critical,1.2.840.114283.100.0.10.2.1.0
EOF
)

>serial.txt
>database.txt

openssl req -x509                                     \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1  \
    -config <(echo "$config")                         \
    -extensions ca_kloc                               \
    -subj "/CN=Example OCE Root CA Certificate/"      \
    -keyout sk.ca-kloc.ecdsa.pem -out cert.ca-kloc.ecdsa.pem

openssl req                                           \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1  \
    -config <(echo "$config")                         \
    -reqexts ka_kloc                                  \
    -subj "/CN=Example OCE Intermediate Certificate/" \
    -keyout sk.ka-kloc.ecdsa.pem -out cert.ka-kloc.ecdsa.csr

openssl ca                                            \
    -batch -notext                                    \
    -cert cert.ca-kloc.ecdsa.pem                      \
    -keyfile sk.ca-kloc.ecdsa.pem                     \
    -config <(echo "$config")                         \
    -policy signing_policy -extensions signing_req    \
    -outdir .                                         \
    -rand_serial                                      \
    -out cert.ka-kloc.ecdsa.pem -infiles cert.ka-kloc.ecdsa.csr

openssl req                                           \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1  \
    -config <(echo "$config")                         \
    -reqexts oce                                      \
    -subj "/CN=Example OCE Certificate/"              \
    -keyout sk.oce.ecka.pem -out cert.oce.ecka.csr

openssl ca                                            \
    -batch -notext                                    \
    -cert cert.ka-kloc.ecdsa.pem                      \
    -keyfile sk.ka-kloc.ecdsa.pem                     \
    -config <(echo "$config")                         \
    -policy signing_policy -extensions signing_req    \
    -outdir .                                         \
    -rand_serial                                      \
    -out cert.oce.ecka.pem -infiles cert.oce.ecka.csr

cat cert.ka-kloc.ecdsa.pem cert.ca-kloc.ecdsa.pem > certs.oce.pem

openssl pkcs12                                        \
    -export                                           \
    -out oce.pfx                                      \
    -inkey sk.oce.ecka.pem                            \
    -in cert.oce.ecka.pem                             \
    -certfile certs.oce.pem                           \
    -passout pass:password

cp cert*.pem ..
cp sk.oce.ecka.pem ..
cp oce.pfx ..
