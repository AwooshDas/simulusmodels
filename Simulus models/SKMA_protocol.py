
import simulus
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class Node:
    def __init__(self, sim, id, nodes):
        self.sim = sim
        self.id = id
        self.channel_busy = False
        self.private_key = None
        self.public_key = None
        self.nodes = nodes

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
        if not self.channel_busy:
            print("RTU Node %d starts transmitting data packet to Node %d at %g" % (self.id, sink.id, self.sim.now))
            transmission_time = random.uniform(0.5, 2)  # Random transmission time between 0.5 and 2
            self.sim.sleep(transmission_time)
            self.channel_busy = True

            # Simulate network delay/failure
            if random.random() < 0.1:  # 10% chance of failure
                print("Transmission from Node %d to Node %d failed at %g" % (self.id, sink.id, self.sim.now))
                self.channel_busy = False
            else:
                encrypted_data = self.encrypt_data(data, recipient_public_key)
                print("RTU Node %d finishes transmitting encrypted data packet to Node %d at %g" % (self.id, sink.id, self.sim.now))
                sink.receive_data_packet(encrypted_data, self.public_key)

                channel_busy_time = random.uniform(0.5, 2)  # Random channel busy time between 0.5 and 2
                self.sim.sleep(channel_busy_time)
                self.channel_busy = False

    def broadcast_data(self, data):
        for node in self.nodes:
            if node != self:
                encrypted_data = self.encrypt_data(data, node.public_key)
                node.receive_data_packet(encrypted_data, self.public_key)

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
        else:
            print("RTU Node %d received data from an unknown sender at %g" % (self.id, self.sim.now))


def master_station(sim, num_nodes):
    random.seed(27)  # Set seed value for consistent results
    nodes = [Node(sim, i, []) for i in range(num_nodes)]  # Initialize nodes dynamically
    for node in nodes:
        node.generate_key_pair()
        node.nodes = nodes
    while True:
        # Generate random data from master station
        data = "(Sample data)"
        source_node = random.choice(nodes)  # Select a random source node
        destination_node = random.choice(nodes)  # Select a random destination node

        print("Master station broadcasts data %s" % data)
        source_node.transmit_data_packet(destination_node, data, destination_node.public_key)
        source_node.broadcast_data(data)

        sim.sleep(random.uniform(1, 5))  # Random time between successive broadcasts


sim = simulus.simulator()
sim.process(master_station, sim, num_nodes=10)  # Change the num_nodes value to the desired number of nodes
sim.run(until=5)  # Run the simulation for n times