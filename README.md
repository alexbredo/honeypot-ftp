honeypot-ftp-python3
============

Adapted from https://github.com/alexbredo/honeypot-ftp FTP Honeypot by Alexander Bredo.
Minor changes to allow for more lightweight logging, elasticsearch support and command line flags including a more verbose output.

Features:
 * FTP + SSL-FTP
 * Catch used credentials
 * Catch malware files
 * distribute honeytoken files

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
# Run
python3 ftp.py -help
```
 
Contribution welcome.

FAQ
===
1) Generate SSL-Certificates

CA:
openssl genrsa -out ca.private.key 4096
openssl req -new -x509 -days 4096 -key ca.private.key -out ca.public.key

SRV:
openssl genrsa -out smtp.private.key 4096
openssl req -new -key smtp.private.key -out smtp.csr
openssl x509 -req -days 1024 -in smtp.csr -CA ca.public.key -CAkey ca.private.key -set_serial 01 -out smtp.public.key

SSL Check Connection
openssl s_client -quiet -connect 127.0.0.1:990

2) Known Errors
OpenSSL.SSL.Error: [('system library', 'fopen', 'No such process'), ('BIO routines', 'FILE_CTRL', 'system lib'), ('SSL routines', 'SSL_CTX_use_certificate_file', 'system lib')]
 --> Certifcate Files not found (wrong path?)

All rights reserved.
(c) 2014 by Alexander Bredo, 2024 James Brine
