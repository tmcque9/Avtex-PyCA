import sys
from optparse import OptionParser, OptionGroup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pprint import pprint
from ipaddress import IPv4Address

def main(argv):
    private_key = None

    parser = OptionParser()
    
    parser.add_option("-k", "--keyfile", dest="key_filename", help="file that contains the private key", metavar="KEYFILE")
    parser.add_option("-o", "--output", dest="output_file", help="filename to write the certificate request to", metavar="OUTPUT")

    csr_group = OptionGroup(parser, "Certificate Signing Request Options")
    csr_group.add_option("-C", "--country", dest="country", help="Country Name", metavar="COUNTRY", default="US")
    csr_group.add_option("-S", "--state", dest="state", help="State Name", metavar="STATE", default="Minnesota")
    csr_group.add_option("-L", "--locality", dest="locality", help="Locality Name", metavar="LOCALITY", default="Minneapolis")
    csr_group.add_option("-O", "--organization", dest="organization", help="Organization Name", metavar="ORGANIZATION", default="Avtex")
    csr_group.add_option("-U", "--organizationUnit", dest="organizational_unit", help="Organization Unit Name", metavar="ORGANIZATIONAL UNIT", default="Avtex CC")
    csr_group.add_option("-N", "--commonName", dest="common_name", help="Common Name", metavar="COMMNON_NAME", default="Test Certificate")

    parser.add_option_group(csr_group)

    san_group = OptionGroup(parser, "Subject Alternate Name Options")
    san_group.add_option("-D", "--dns", dest="dns_addresses", help="Alternate DNS Address", metavar="DNS", action="append")
    san_group.add_option("-I", "--ip", dest="ip_addresses", help="Alternate IP Address", metavar="IP", action="append")

    parser.add_option_group(san_group)

    key_group = OptionGroup(parser, "Private Key Options")
    key_group.add_option('--size', dest="key_size", help="Private Key Size (in bytes, defaults to 2048)", metavar="BYTES", default=2048)
    key_group.add_option('--exp', '--exponent', dest="key_exponent", help="Private Key Exponent Size (defaults to 65537)", metavar="SIZE", default=65537)
    key_group.add_option('--keyfilename', dest="key_output_filename", help="Private Key Filename", metavar="NAME")

    parser.add_option_group(key_group)

    if len(sys.argv) == 1:
        parser.parse_args(['--help'])
        sys.exit(1)

    options, args = parser.parse_args()
    # print('arguments', args)
    print('options', options)
    
    if options.key_filename == None:
        private_key = generate_key(options)
    else:
        private_key = open_key_file(options.key_filename)

    builder = x509.CertificateSigningRequestBuilder()
    builder = generate_csr(builder, options)
    builder = add_sans(builder, options)

    csr = builder.sign(private_key = private_key, algorithm = hashes.SHA256(), backend = default_backend())

    with open(options.output_file, "wb") as csr_output:
        csr_output.write(csr.public_bytes(serialization.Encoding.PEM))

    if options.key_output_filename != None:
        with open(options.key_output_filename, "wb") as key_output:
            key_output.write(private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            ))

    sys.exit()
   
def generate_csr(builder, options):
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, options.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, options.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, options.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, options.organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, options.organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, options.common_name)
    ]))
    return builder

def add_sans(builder, options):
    alternate_names = []
    if options.dns_addresses:
        for dns_address in options.dns_addresses:
            alternate_names.append(x509.DNSName(dns_address))

    if options.ip_addresses:
        for ip_address in options.ip_addresses:
            alternate_names.append(x509.IPAddress(IPv4Address(ip_address)))

    return builder.add_extension(x509.SubjectAlternativeName(alternate_names), critical=False)

def print_usage():
    print("make_csr.py -k <keyFile> -o <outputFile>")
    sys.exit(2)

def open_key_file(keyfile):
    with open(keyfile, 'rb') as private_key_file:
        return serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

def generate_key(options):
    return rsa.generate_private_key (
        public_exponent = options.key_exponent,
        key_size = options.key_size,
        backend = default_backend()
    )

if __name__ == "__main__":
    main(sys.argv[1:])