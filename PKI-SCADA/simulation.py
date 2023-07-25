import simulus
import random
from X509 import X509CertificateAuthority
import numpy as np
from MTU import MTU
from RTU import RTU

polling_rate = 5 # define polling interval for polling functionality
num_nodes = 10
certificate_authority = X509CertificateAuthority()
sim = simulus.simulator()
nodes = [RTU(sim, i, [], certificate_authority) for i in range(num_nodes)]  # Initialize nodes dynamically
master_station = MTU(sim, [], certificate_authority)
nodes.append(master_station)

def model(sim):
    random.seed(400)  # Set seed value for consistent results
    for node in nodes:
        node.generate_key_pair()
        node.nodes = nodes

    while True:
        # Generate random data from master station
        data = "(Sample data)"
        source_node = random.choice(nodes)  # Select a random source node
        possible_destinations = [node for node in nodes if node != source_node]

        # Select a random destination node or nodes with a 50/50 chance
        if random.random() < 0.5:  # 50% chance of unicast
            destination_sink = random.choice(possible_destinations)  # Select a random destination node
        else:  # 50% chance of multicast/broadcast
            num_destination_nodes = random.randint(2, len(possible_destinations))
            destination_sink = random.sample(possible_destinations, num_destination_nodes)

        if source_node == master_station:
            source_node.generate_certificate("Master Station")
            source_node.save_certificate("MTU_cert.pem")
            source_node.load_certificate("MTU_cert.pem")
            source_node.print_certificate()
        else:
            source_node.generate_certificate("RTU %d" % source_node.id)
            source_node.save_certificate("RTU%d_cert.pem" % source_node.id)
            source_node.load_certificate("RTU%d_cert.pem" % source_node.id)
            source_node.print_certificate()

        # Check if destination_sink is a list or a single node and call transmit function accordingly
        if isinstance(destination_sink, list):
            recipient_public_keys = [node.public_key for node in destination_sink]
            source_node.transmit_data_packet(destination_sink, data, recipient_public_keys, nodes)
        else:
            source_node.transmit_data_packet(destination_sink, data, destination_sink.public_key, nodes)

        #if sim.now % polling_rate <= 2:  # Perform polling only after the specified interval
            #source_node.perform_polling()
        
        # Simulate Certificate Revocation and Update
        if random.random() < 0.05:  # 5% chance of certificate revocation/update
            if random.random() < 0.5:  # 50% chance of certificate revocation
                node_to_revoke = random.choice(nodes)
                if node_to_revoke.id == "Master Station":
                    if node_to_revoke.certificate:
                        print("Certificate of Master Station is revoked at %g" % ( sim.now))
                        # Remove the revoked node from the list of nodes
                        nodes.remove(node_to_revoke)
                        # Add a new node to replace the revoked one
                        new_node = MTU(sim, node_to_revoke.id, [], certificate_authority)
                        new_node.nodes = nodes
                        nodes.append(new_node)
                        print("Updated Master Station is installed to replace the previous node with revoked certificate at %g" % (sim.now))
                    else:
                        print("Master Station does not have a certificate to revoke at %g" % (node_to_revoke.id, sim.now))
                else:
                    if node_to_revoke.certificate:
                        print("Certificate of RTU %d is revoked at %g" % (node_to_revoke.id, sim.now))
                        # Remove the revoked node from the list of nodes
                        nodes.remove(node_to_revoke)
                        # Add a new node to replace the revoked one
                        new_node = RTU(sim, node_to_revoke.id, [], certificate_authority)
                        new_node.nodes = nodes
                        nodes.append(new_node)
                        print("Updated RTU %d is installed to replace the previous node with revoked certificate at %g" % (new_node.id, sim.now))
                    else:
                        print("RTU %d does not have a certificate to revoke at %g" % (node_to_revoke.id, sim.now))
            else:  # 50% chance of certificate update
                node_to_update = random.choice(nodes)
                if node_to_update.id == "Master Station":
                    if node_to_update.certificate:
                        new_certificate_subject_name = "Updated Master Station Certificate"
                        node_to_update.generate_certificate(new_certificate_subject_name)
                        node_to_update.update_certificate(node_to_update.certificate)
                        print("Certificate of Master Station is updated at %g" % (sim.now))
                    else:
                        print("Master Station does not have a certificate to update at %g" % (sim.now))
                else:
                    if node_to_update.certificate:
                        new_certificate_subject_name = "Updated RTU %d Certificate" % node_to_update.id
                        node_to_update.generate_certificate(new_certificate_subject_name)
                        node_to_update.update_certificate(node_to_update.certificate)
                        print("Certificate of RTU %d is updated at %g" % (node_to_update.id, sim.now))
                    else:
                        print("RTU %d does not have a certificate to update at %g" % (node_to_update.id, sim.now))

        # Simulate CRL Generation and Management
        if sim.now % (polling_rate * 6) <= 0.9:  # Load and check CRL every six polling intervals
            loaded_crl = source_node.load_crl("crl.pem")
            revoked_certificate = random.choice(nodes).certificate
            if isinstance(revoked_certificate, RTU):
                if revoked_certificate:
                    if source_node.is_certificate_revoked(revoked_certificate):
                        print("Certificate of RTU %d is revoked according to the CRL at %g" % (revoked_certificate.id, sim.now))
                    else:
                        print("Certificate of RTU %d is not revoked according to the CRL at %g" % (revoked_certificate.id, sim.now))
                else:
                    print("Randomly chosen RTU does not have a certificate to check against CRL at %g" % sim.now)
            elif isinstance(revoked_certificate, MTU):
                if revoked_certificate:
                    if source_node.is_certificate_revoked(revoked_certificate):
                        print("Certificate of Master Station is revoked according to the CRL at %g" % (sim.now))
                    else:
                        print("Certificate of Master Station is not revoked according to the CRL at %g" % (sim.now))
                else:
                    print("Master Station does not have a certificate to check against CRL at %g" % sim.now)

        
        sim.sleep(random.uniform(1, 5))  # Random time between successive sending

sim.process(model, sim)  # Change the num_nodes value to the desired number of nodes
sim.run(until=500)  # Run the simulation until time n

for node in nodes:
    node.perform_polling()