from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from datetime import datetime, timedelta
import base64
import random
import numpy as np

class X509CertificateAuthority:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = None

    def generate_certificate(self, subject_name):
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_name)
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "CN=ModelCertificateAuthority, OU=CybersecurityDivision, O=ITI, C=USA")
        ]))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        self.certificate = builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
        )

    def save_certificate(self, filename):
        with open(filename, "wb") as file:
            file.write(self.certificate.public_bytes(encoding=serialization.Encoding.PEM))

    def load_certificate(self, filename):
        with open(filename, "rb") as file:
            cert_data = file.read()
            self.certificate = load_pem_x509_certificate(cert_data)

    def get_certificate(self):
        return self.certificate

    def get_private_key(self):
        return self.private_key
