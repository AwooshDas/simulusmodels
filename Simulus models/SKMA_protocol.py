import simulus
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from X509 import X509CertificateAuthority, X509Node
import numpy as np

average_transmission_time = random.uniform(1, 10)
average_channel_busy_time = random.uniform(1, 5)
polling_rate = 5 # define polling interval for polling functionality
class Node:
    def __init__(self, sim, id, nodes):
        self.sim = sim
        self.id = id
        self.channel_busy = False
        self.private_key = None # node private key 
        self.public_key = None # node public key
        self.nodes = nodes
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


def master_station(sim, num_nodes):
    certificate_authority = X509CertificateAuthority()
    random.seed(500)  # Set seed value for consistent results
    nodes = [X509Node(sim, i, [], certificate_authority) for i in range(num_nodes)]  # Initialize nodes dynamically
    for node in nodes:
        node.generate_key_pair()
        node.nodes = nodes

    while True:
        # Generate random data from master station
        data = "(Sample data)"
        source_node = random.choice(nodes)  # Select a random source node
        destination_node = random.choice(nodes)  # Select a random destination node
        
        broadcast_probabilities = [0.75, 0.25]  # Probabilities of not broadcasting and broadcasting respectively
        broadcast_decision = random.choices([False, True], broadcast_probabilities)[0]  # Choose False (no broadcast) or True (broadcast) based on probabilities
        
        if broadcast_decision:
            print("Master station broadcasts data %s to all RTU Nodes at %g " % (data, sim.now))
        
        source_node.transmit_data_packet(destination_node, data, destination_node.public_key)
        if sim.now % polling_rate <= 2:  # Perform polling only after the specified interval
            transmissions, receptions, failed_transmissions = source_node.perform_polling()
            print("POLLING RESULTS: Source Node %d - Transmissions: %d, Receptions: %d, Failed Transmissions: %d" % (source_node.id, transmissions, receptions, failed_transmissions))
        source_node.generate_certificate("Node %d" % source_node.id)
        source_node.save_certificate("node%d_cert.pem" % source_node.id)
        source_node.load_certificate("node%d_cert.pem" % source_node.id)
        source_node.print_certificate()
        

        sim.sleep(random.uniform(1, 5))  # Random time between successive broadcasts



sim = simulus.simulator()
sim.process(master_station, sim, num_nodes=10)  # Change the num_nodes value to the desired number of nodes
sim.run(until=100)  # Run the simulation for n times


