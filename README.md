## dane_tlsagen

Generates a TLSA DNS record for the given port, protocol and certificate. \
\
**Usage:**
```
dane_tlsagen.py FIELDS -port PORT -proto PROTO -cert PATH_TO_CERTIFICATE
```

**Example:**
```
$ dane_tlsagen.py 311 --port 443 --proto tcp --domain service.example.com --cert /etc/letsencrypt/live/service.example.com/cert.pem
_443._tcp.service.example.com. IN TLSA 3 1 1 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
```
\
**Further information:** \
https://www.internetsociety.org/resources/deploy360/dane/ \
https://tools.ietf.org/html/rfc6698 \
https://www.huque.com/bin/gen_tlsa \
https://www.huque.com/bin/danecheck
