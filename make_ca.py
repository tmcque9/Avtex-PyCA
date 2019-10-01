from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import uuid

# private_key_path = r'Certificates\LinesAuthority\DefaultLinesAuthority\LinesAuthorityPrivateKey.bin'

# with open(private_key_path, 'rb') as private_key_file:
#     private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

PUBLIC_EXPONENT = int(input("Public Exponent (default 65537): ") or 65537)
KEY_SIZE = int(input("Key Size (default 2048): ") or 2048)

private_key = rsa.generate_private_key (
    public_exponent = PUBLIC_EXPONENT,
    key_size = KEY_SIZE,
    backend = default_backend()
)

ORGANIZATION_NAME = input("ORGANIZATION_NAME: ") or "Avtex"
ORGANIZATIONAL_UNIT_NAME = input("ORGANIZATIONAL_UNIT_NAME: ") or "CC Development"
COMMON_NAME = input("COMMON_NAME: ") or "Avtex CC Development CA"

name = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ORGANIZATIONAL_UNIT_NAME),
    x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
])

builder = x509.CertificateBuilder()
builder = builder.subject_name(name)
builder = builder.issuer_name(name)

builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3649))

builder = builder.serial_number(int(uuid.uuid1()))
builder = builder.public_key(private_key.public_key())

builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

CERTIFICATE_PREFIX = input("Certificate Name Prefix (no extension): ") or "certificate"

with open(CERTIFICATE_PREFIX + ".cer", 'wb') as f:
    f.write(cert.public_bytes(encoding = serialization.Encoding.PEM))

# PASSPHRASE = input("Private Key Passphrase (Enter for none): ")

with open(CERTIFICATE_PREFIX + "_private.key", 'wb') as g:
    g.write(private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    ))