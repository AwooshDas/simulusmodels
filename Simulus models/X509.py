from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography import x509
from datetime import datetime, timedelta
import base64
import random
import numpy as np

average_transmission_time = random.uniform(0.001, 0.01)
average_channel_busy_time = random.uniform(0.001, 0.05)
polling_rate = 5 # define polling interval for polling functionality

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


class X509Node:
    def __init__(self, sim, id, nodes, certificate_authority):
        self.sim = sim
        self.id = id
        self.channel_busy = False
        self.private_key = None # node private key 
        self.public_key = None # node public key
        self.certificate = None
        self.nodes = nodes
        self.certificate_authority = certificate_authority
        self.poll_interval = polling_rate
        self.transmissions = 0  # Number of data transmissions
        self.receptions = 0  # Number of data receptions
        self.failed_transmissions = 0  # Number of failed transmissions

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def generate_certificate(self, subject_name):
        self.certificate_authority.generate_certificate(subject_name)
        self.certificate = self.certificate_authority.get_certificate()

    def save_certificate(self, filename):
        self.certificate_authority.save_certificate(filename)

    def load_certificate(self, filename):
        self.certificate_authority.load_certificate(filename)
        self.certificate = self.certificate_authority.get_certificate()

    def print_certificate(self):
        if self.certificate:
            cert = self.certificate
            print("Certificate Details:")
            print("Subject Name:", cert.subject.rfc4514_string())
            print("Issuer Name:", cert.issuer.rfc4514_string())
            print("Serial Number:", cert.serial_number)
            print("Not Valid Before:", cert.not_valid_before)
            print("Not Valid After:", cert.not_valid_after)
            print("Public Key:", cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
        else:
            print("No certificate loaded.")

    def encrypt_data(self, data, recipient_public_key):
        ciphertext = recipient_public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_data(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def transmit_data_packet(self, sink, data, recipient_public_key):
        if not self.channel_busy and self != sink:
            print("RTU Node %d starts transmitting data packet to Node %d at %g" % (self.id, sink.id, self.sim.now))
            transmission_time = np.random.exponential(average_transmission_time)
            self.sim.sleep(transmission_time)
            self.channel_busy = True

            # Simulate network delay/failure
            if random.random() < 0.1:  # 10% chance of failure
                print("Transmission from Node %d to Node %d failed at %g" % (self.id, sink.id, self.sim.now))
                self.channel_busy = False
                self.failed_transmissions += 1 # Increment failed transmissions count
            else:
                encrypted_data = self.encrypt_data(data, recipient_public_key)
                print("RTU Node %d finishes transmitting encrypted data packet to Node %d at %g" % (self.id, sink.id, self.sim.now))
                self.transmissions += 1  # Increment transmissions count
                sink.receive_data_packet(encrypted_data, self.public_key)

                channel_busy_time = np.random.exponential(average_channel_busy_time)
                self.sim.sleep(channel_busy_time)
                self.channel_busy = False

    def receive_data_packet(self, encrypted_data, sender_public_key):
        decrypted_data = self.decrypt_data(encrypted_data)
        sender_node = None
        for node in self.nodes:
            if node.public_key == sender_public_key:
                sender_node = node
                break
        if sender_node is not None:
            sender_node_id = sender_node.id
            sender_public_key_str = sender_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            print("RTU Node %d received decrypted data '%s' from Node %d with public key:\n%s\nat %g" % (self.id, decrypted_data, sender_node_id, sender_public_key_str, self.sim.now))
            self.receptions += 1  # Increment receptions count
        else:
            print("RTU Node %d received data from an unknown sender at %g" % (self.id, self.sim.now))
    
    def perform_polling(self):
        # Simulate polling operation and return data

        transmissions = self.transmissions
        receptions = self.receptions
        failed_transmissions = self.failed_transmissions

        return transmissions, receptions, failed_transmissions