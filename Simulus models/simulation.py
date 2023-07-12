import simulus
import random
from X509 import X509CertificateAuthority
import numpy as np
from MTU import MTU
from RTU import RTU

average_transmission_time = random.uniform(1, 10)
average_channel_busy_time = random.uniform(1, 5)
polling_rate = 5 # define polling interval for polling functionality
num_nodes = 10
certificate_authority = X509CertificateAuthority()
sim = simulus.simulator()
nodes = [RTU(sim, i, [], certificate_authority) for i in range(num_nodes)]  # Initialize nodes dynamically
master_station = MTU(sim, [], certificate_authority)
nodes.append(master_station)

def model(sim):
    random.seed(101)  # Set seed value for consistent results
    for node in nodes:
        node.generate_key_pair()
        node.nodes = nodes

    while True:
        # Generate random data from master station
        data = "(Sample data)"
        source_node = random.choice(nodes)  # Select a random source node
        destination_node = random.choice(nodes)  # Select a random destination node
        
        source_node.transmit_data_packet(destination_node, data, destination_node.public_key)
        if sim.now % polling_rate <= 2:  # Perform polling only after the specified interval
            source_node.perform_polling()
        if source_node == master_station:
            source_node.generate_certificate("Master Station")
            source_node.save_certificate("MTU_cert.pem")
            source_node.load_certificate("MTU_cert.pem")
            source_node.print_certificate()
        else :
            source_node.generate_certificate("RTU %d" % source_node.id)
            source_node.save_certificate("RTU%d_cert.pem" % source_node.id)
            source_node.load_certificate("RTU%d_cert.pem" % source_node.id)
            source_node.print_certificate()
        

        sim.sleep(random.uniform(1, 5))  # Random time between successive broadcasts

sim.process(model, sim)  # Change the num_nodes value to the desired number of nodes
sim.run(until=100)  # Run the simulation for n times

for node in nodes:
    node.perform_polling()