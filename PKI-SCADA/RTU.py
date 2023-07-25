import simulus
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from X509 import X509CertificateAuthority
import numpy as np

average_packet_ready_time = random.uniform(1, 5)
average_send_time = random.uniform(1, 10)
average_channel_busy_time = random.uniform(1, 15)
polling_rate = 5 # define polling interval for polling functionality

class RTU:
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
    
    def revoke_certificate(self, certificate_to_revoke):
        self.certificate_authority.revoke_certificate(certificate_to_revoke)

    def is_certificate_revoked(self, certificate_to_check):
        return self.certificate_authority.is_certificate_revoked(certificate_to_check)

    def update_certificate(self, new_certificate):
        self.certificate_authority.update_certificate(new_certificate)

    def generate_crl(self):
        return self.certificate_authority.generate_crl()

    def save_crl(self, crl, filename):
        self.certificate_authority.save_crl(crl, filename)

    def load_crl(self, filename):
        return self.certificate_authority.load_crl(filename)

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

    def transmit_data_packet(self, sink, data, recipient_public_keys, all_nodes):
        if not self.channel_busy and self != sink:
            # Check if sink is a list and handle multicast or broadcast
            if isinstance(sink, list):
                if len(sink) == 1:
                    if sink[0].id == "Master Station":
                        print("RTU %d starts transmitting data packet to Master Station at %g" % (self.id, self.sim.now))
                    else:
                        print("RTU %d starts transmitting data packet to RTU %d at %g" % (self.id, sink[0].id, self.sim.now))
                elif len(sink) > 1 and len(sink) < len(all_nodes):
                    sink_ids = [node.id for node in sink]
                    if "Master Station" in sink_ids:
                        sink_ids.remove("Master Station")
                        print("RTU %d multicasts data packet to RTUs %s, and Master Station at %g" % (self.id, ', '.join(map(str, sink_ids)), self.sim.now))
                    else:
                        print("RTU %d multicasts data packet to RTUs %s at %g" % (self.id, ', '.join(map(str, sink_ids)), self.sim.now))
                else:
                    print("RTU %d broadcasts data packet to all RTUs and Master Station at %g" % (self.id, self.sim.now))
            else:
                if sink.id == "Master Station":
                    print("RTU %d starts transmitting data packet to Master Station at %g" % (self.id, self.sim.now))
                else:
                    print("RTU %d starts transmitting data packet to RTU %d at %g" % (self.id, sink.id, self.sim.now))

            transmission_time = np.random.exponential(average_packet_ready_time)
            self.sim.sleep(transmission_time)
            self.channel_busy = True

            # Simulate network delay/failure for each sink node
            if isinstance(sink, list):
                for node, recipient_key in zip(sink, recipient_public_keys):
                    if random.random() < 0.1:  # 10% chance of failure for each node in a multicast scenario
                        if node.id == "Master Station":
                            print("Transmission from RTU %d to Master Station failed at %g" % (self.id, self.sim.now))
                        else:
                            print("Transmission from RTU %d to RTU %d failed at %g" % (self.id, node.id, self.sim.now))
                        self.failed_transmissions += 1  # Increment failed transmissions count
                    else:
                        encrypted_data = self.encrypt_data(data, recipient_key)
                        if node.id == "Master Station":
                            print ("RTU %d finishes transmitting encrypted data packet to Master Station at %g" % (self.id, self.sim.now))
                        else:
                            print("RTU %d finishes transmitting encrypted data packet to RTU %d at %g" % (self.id, node.id, self.sim.now))
                        self.transmissions += 1  # Increment transmissions count
                        send_time = np.random.exponential(average_send_time)
                        self.sim.sleep(send_time)
                        self.channel_busy = True
                        node.receive_data_packet(encrypted_data, self.public_key)
            else:
                if random.random() < 0.1:  # 10% chance of failure
                    if sink.id == "Master Station":
                        print("Transmission from RTU %d to Master Station failed at %g" % (self.id, self.sim.now))
                    else:
                        print("Transmission from RTU %d to RTU %d failed at %g" % (self.id, sink.id, self.sim.now))
                    self.failed_transmissions += 1  # Increment failed transmissions count
                else:
                    encrypted_data = self.encrypt_data(data, recipient_public_keys)
                    if sink.id == "Master Station":
                        print ("RTU %d finishes transmitting encrypted data packet to Master Station at %g" % (self.id, self.sim.now))
                    else:
                        print("RTU %d finishes transmitting encrypted data packet to RTU %d at %g" % (self.id, sink.id, self.sim.now))
                    self.transmissions += 1  # Increment transmissions count
                    send_time = np.random.exponential(average_send_time)
                    self.sim.sleep(send_time)
                    self.channel_busy = True
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
            if sender_node.id == "Master Station":
                print("RTU Node %d received decrypted data '%s' from Master Station with public key:\n%s\nat %g" % (self.id, decrypted_data, sender_public_key_str, self.sim.now))
            else:
                print("RTU Node %d received decrypted data '%s' from RTU Node %d with public key:\n%s\nat %g" % (self.id, decrypted_data, sender_node_id, sender_public_key_str, self.sim.now))
            self.receptions += 1  # Increment receptions count
        else:
            print("RTU Node %d received data from an unknown sender at %g" % (self.id, self.sim.now))
    
    def perform_polling(self):
        # Simulate polling operation and return data

        transmissions = self.transmissions
        receptions = self.receptions
        failed_transmissions = self.failed_transmissions

        print("POLLING RESULTS: Source RTU %d - Transmissions: %d, Receptions: %d, Failed Transmissions: %d" % (self.id, transmissions, receptions, failed_transmissions))