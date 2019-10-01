import sys
from optparse import OptionParser, OptionGroup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.extensions import ExtensionType, Extension
import datetime
import uuid
from pprint import pprint


def main():

    CA_CERT = None
    CA_KEY = None
    CSR = None

    parser = OptionParser()
    
    parser.add_option("--cafile", dest="ca_file", help="file that contains the CA certificate", metavar="CERT")
    parser.add_option("--cakey", dest="ca_key", help="file that contains the CA private key", metavar="KEY")
    parser.add_option("--csr", dest="csr_file", help="file that contains the Certificate Signing Request", metavar="CSR")
    parser.add_option("-o", "--out", dest="cert_file", help="file to write the certificate to", metavar="FILE", default="signed.cert")

    if len(sys.argv) == 1:
        parser.parse_args(['--help'])
        sys.exit(1)

    options, args = parser.parse_args()

    if not options.ca_file:
        parser.error("CA File not specified")

    if not options.ca_key:
        parser.error("CA Private Key not specified")

    if not options.csr_file:
        parser.error("CSR File not specified")

    with open(options.ca_key, 'rb') as private_key_file:
        CA_KEY = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

    with open(options.ca_file, 'rb') as cert_authority_file:
        CA_CERT = x509.load_pem_x509_certificate(cert_authority_file.read(), backend = default_backend())

    with open(options.csr_file, "rb") as cert_req_file:
        CSR = x509.load_pem_x509_csr(cert_req_file.read(), default_backend())

    # pprint(CSR.extensions)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(CSR.subject)
    builder = builder.issuer_name(CA_CERT.subject)
    builder = builder.public_key(CSR.public_key())
    builder = builder.serial_number(uuid.uuid4().int)
    builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3649))
    for extension in CSR.extensions:
        # pprint(extension)
        # if not isinstance(extension, ExtensionType):
        #     print("FOOOOOOOOO")
    # print()
    # pprint(CSR.extensions)
    # print()
    # sys.exit()
        builder = builder.add_extension(extension.value, critical=extension.critical)
    cert = builder.sign(private_key=CA_KEY, algorithm=hashes.SHA256(), backend=default_backend())

    with open(options.cert_file, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    sys.exit()

if __name__ == "__main__":
    main()
