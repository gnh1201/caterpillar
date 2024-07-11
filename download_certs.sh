#!/bin/sh
wget https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/ca.crt
wget https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/ca.key
wget https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/cert.key

# echo "if you want generate a certificate..."
#openssl genrsa -out ca.key 2048
#openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=php-httpproxy CA"
#openssl genrsa -out cert.key 2048
