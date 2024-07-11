@echo off
bitsadmin /transfer certsjob /download /priority normal https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/ca.crt %CD%\ca.crt
bitsadmin /transfer certsjob /download /priority normal https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/ca.key %CD%\ca.key
bitsadmin /transfer certsjob /download /priority normal https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/cert.key %CD%\cert.key
bitsadmin /transfer certsjob /download /priority normal https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/cert.key %CD%\default.crt

REM echo if you want generate a certificate...
REM openssl genrsa -out ca.key 2048
REM openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=php-httpproxy CA"
REM openssl genrsa -out cert.key 2048
