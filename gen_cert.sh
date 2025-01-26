#!/bin/sh

openssl genpkey -algorithm RSA -out private_key.pem

openssl req -new -key private_key.pem -out server.csr

openssl x509 -req -in server.csr -signkey private_key.pem -out server_cert.pem -days 365

openssl x509 -in server_cert.pem -text -noout
