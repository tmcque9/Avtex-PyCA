from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import uuid
from pprint import pprint


private_key_path = r'Certificates\LinesAuthority\DefaultLinesAuthority\LinesAuthorityPrivateKey.bin'
# cert_auth_path = r'Certificates\LinesAuthority\DefaultLinesAuthority\LinesAuthorityCertificate.cer'
# private_key_path = r'Certificates\CIC01_PrivateKey.bin'
cert_auth_path = r'lines_ca_sha1.cer'

with open(private_key_path, 'rb') as private_key_file:
    key_file = private_key_file.read()
    print(key_file)
    print()
    private_key = serialization.load_pem_private_key(key_file, password=None, backend=default_backend())

# with open("Certificates/CC01_PublicKey.bin", "rb") as public_key_file
#     public_key = serialization.load_pem_public_key(private_key_file.read(), password=NONE, backend=default_backend());

# print(private_key.key_size)

with open(cert_auth_path, 'rb') as cert_authority_file:
    ca_file = cert_authority_file.read()
    print(ca_file)
    print()
    ca = x509.load_pem_x509_certificate(ca_file, default_backend())

with open(r'requests\00001.req', "rb") as cert_req_file:
    csr = x509.load_pem_x509_csr(cert_req_file.read(), default_backend())


builder = x509.CertificateBuilder()
builder = builder.subject_name(csr.subject)
builder = builder.issuer_name(ca.subject)
builder = builder.public_key(csr.public_key())
builder = builder.serial_number(uuid.uuid4().int)
builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3649))
# builder = builder.add_extension(extension=x509.KeyUsage(
#     digital_signature=True, key_encipherment=True, content_commitment=True,
#     data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False,
#     key_cert_sign=False, crl_sign=False
# ), critical=True)
# builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
# builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False)

cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())


with open("00005.cer", "wb") as f:
    f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

# public_key = private_key.public_key()



# builder = x509.CertificateBuilder()

# print(cert_req.subject)
# print(ca.subject)

# builder = builder.subject_name(cert_req.subject)
# builder = builder.issuer_name(ca.subject)
# builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(-1, 0, 0))
# builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(3649, 0, 0))
# builder = builder.serial_number(x509.random_serial_number())

# print('--- begin public_key ---')
# pprint(vars(cert_req))
# print('--- end public_key ---')
# builder = x509.
# builder = x509.CertificateSigningRequestBuilder()
# builder = builder.subject_name(cert_req.subject)

# builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

# cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

# builder = builder.public_key(cert_req.key)

# cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
