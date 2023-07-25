from cryptography.x509 import load_pem_x509_certificate, CertificateRevocationListBuilder
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
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
        self.ca_signature = None
        self.ca_public_key = None

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
        self.ca_signature = self.certificate.signature
        self.ca_public_key = self.certificate.public_key()

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

    def revoke_certificate(self, certificate_to_revoke):
        # Simulate certificate revocation by removing the revoked certificate from the certificate authority
        if certificate_to_revoke == self.certificate:
            self.certificate = None

    def is_certificate_revoked(self, certificate_to_check):
        # Simulate checking if a certificate is revoked by comparing it with the stored revoked certificates
        return certificate_to_check != self.certificate

    def update_certificate(self, new_certificate):
        # Simulate updating the certificate in the certificate authority
        self.certificate = new_certificate

    def generate_crl(self):
        # Simulate generating a Certificate Revocation List (CRL) containing revoked certificates
        revoked_certificates = [self.certificate]  # Add the revoked certificate(s) to the CRL
        crl_builder = CertificateRevocationListBuilder()
        for revoked_cert in revoked_certificates:
            crl_builder = crl_builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_cert.serial_number)
                .revocation_date(datetime.utcnow())
                .build()
            )
        crl_builder = crl_builder.issuer_name(self.certificate.subject)
        crl_builder = crl_builder.last_update(datetime.utcnow())
        crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=30))
        crl = crl_builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())
        return crl

    def save_crl(self, crl, filename):
        # Simulate saving the Certificate Revocation List (CRL) to a file
        with open(filename, "wb") as file:
            file.write(crl.public_bytes(encoding=serialization.Encoding.PEM))

    def load_crl(self, filename):
        # Simulate loading the Certificate Revocation List (CRL) from a file
        with open(filename, "rb") as file:
            crl_data = file.read()
            crl = x509.load_pem_x509_crl(crl_data)
        return crl
