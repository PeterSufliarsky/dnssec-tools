import argparse
import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# usage example: python dane_tlsagen.py 311 --port 443 --proto tcp --domain service.example.com --cert cert.pem

# parse the command line arguments
parser = argparse.ArgumentParser(description="Generates a TLSA record for DANE based on given parameters.")
optionalArgs = parser._action_groups.pop()
parser.add_argument("fields", type=str, help="Fields")
requiredArgs = parser.add_argument_group('required arguments')
requiredArgs.add_argument("--port", type=int, help="Port", required=True)
requiredArgs.add_argument("--proto", type=str, default="tcp", help="Protocol", required=True)
requiredArgs.add_argument("--domain", type=str, help="Domain name", required=True)
requiredArgs.add_argument("--cert", type=str, help="Path to the certificate in PEM format", required=True)
parser._action_groups.append(optionalArgs)
args = parser.parse_args()

# collect data for the result
usage = args.fields[0]
selector = args.fields[1]
matching_type = args.fields[2]
port = args.port
proto = args.proto
domain = args.domain

# load the certificate in PEM format
with open(args.cert, 'r') as file:
    data = ''.join(line.rstrip() for line in file)
cert_data = data.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")

# get the certificate or SPKI digest
digest = ''
if selector == '0':
    if matching_type == '0':
        digest = base64.b64decode(cert_data).hex()
    elif matching_type == '1':
        m = hashlib.sha256()
        m.update(base64.b64decode(cert_data))
        digest = m.digest().hex()
    else:
        m = hashlib.sha512()
        m.update(base64.b64decode(cert_data))
        digest = m.digest().hex()
else:
    x509_cert = x509.load_der_x509_certificate(base64.b64decode(cert_data), default_backend())
    spki = x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    if matching_type == '0':
        digest = spki.hex()
    elif matching_type == '1':
        m = hashlib.sha256()
        m.update(spki)
        digest = m.digest().hex()
    else:
        m = hashlib.sha512()
        m.update(spki)
        digest = m.digest().hex()

# print result
print("_%d._%s.%s. IN TLSA (%s %s %s %s)" % (port, proto, domain, usage, selector, matching_type, digest))
