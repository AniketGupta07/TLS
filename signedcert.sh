#!/bin/bash
openssl req -out sha1.csr -new -newkey rsa:2048 -nodes -keyout sha1.key
openssl x509 -req -days 360 -in sha1.csr -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out sha1.crt -sha256
openssl x509 -text -noout -in sha1.crt
