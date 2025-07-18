#!/bin/bash

# 1 - files prefix
#     may include path to destination folder
#     or may be used to generate multiple bundles at the same location

prefix="${1}"
basedir=$(dirname ${0})

if [[ -z "${prefix}" ]]; then
    prefix="tests/"
fi

openssl req -nodes -x509 -days 3650 -sha256 -batch -subj "/CN=Test RSA Root CA" \
            -newkey rsa:4096 -keyout ${prefix}ca.key -out ${prefix}ca.crt

openssl req -nodes -sha256 -batch -subj "/CN=Test RSA Intermediate CA" \
            -newkey rsa:3072 -keyout ${prefix}inter.key -out ${prefix}inter.req

openssl req -nodes -sha256 -batch -subj "/CN=test-server.com" \
            -newkey rsa:2048 -keyout ${prefix}end.key -out ${prefix}end.req

openssl rsa -in ${prefix}end.key -out ${prefix}test-server.key

openssl x509 -req -sha256 -days 3650 -set_serial 123 -extensions v3_inter -extfile ${basedir}/openssl.cnf \
             -CA ${prefix}ca.crt -CAkey ${prefix}ca.key -in ${prefix}inter.req -out ${prefix}inter.crt

openssl x509 -req -sha256 -days 2000 -set_serial 456 -extensions v3_end -extfile ${basedir}/openssl.cnf \
             -CA ${prefix}inter.crt -CAkey ${prefix}inter.key -in ${prefix}end.req -out ${prefix}end.crt

rm -rf ${prefix}tls
mkdir -p ${prefix}tls

cat ${prefix}end.crt ${prefix}inter.crt > ${prefix}tls/test-server.pem
cat ${prefix}inter.crt ${prefix}ca.crt > ${prefix}tls/ca.pem
cp ${prefix}end.key ${prefix}tls/test-server.key
cp ${prefix}end.crt ${prefix}ca.crt ${prefix}tls/

rm ${prefix}*.req ${prefix}*.crt ${prefix}*.key
