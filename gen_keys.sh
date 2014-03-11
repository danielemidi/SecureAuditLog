#!/bin/bash

echo Removing previous keys and certificates...
rm -f *.pem

echo Generating keys and certificates...
openssl genrsa -out keyU.pem 2048
# openssl rsa -in keyU.pem -RSAPublicKey_out -out pub-keyU.pem
openssl req \
  -outform PEM -new -x509 -nodes -days 365 \
  -subj '/C=US/ST=Indiana/L=West Lafayette/CN=untrusted.purdue.com' \
  -key keyU.pem -pubkey -out pub-keyU.pem
  
openssl genrsa -out keyT.pem 2048
# openssl rsa -in keyT.pem -RSAPublicKey_out -out pub-keyT2.pem
openssl req \
  -outform PEM -new -x509 -nodes -days 365 \
  -subj '/C=US/ST=Indiana/L=West Lafayette/CN=trusted.purdue.com' \
  -key keyT.pem -pubkey -out pub-keyT.pem
  
echo Complete.