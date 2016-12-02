from scapy.all import *
from scapy.layers.ssl_tls import *
import socket

fichPCAP = "trace.pcap"
nameCert = 1

def find():
    for packet in rdpcap(fichPCAP):
        if packet.haslayer(SSL) or packet.haslayer(TLS):
            if packet.haslayer(X509Cert):
                packet.show()
                directory = str(packet[IP].src)
                if not os.path.exists(directory):
                    os.makedirs(directory)

                #TODO: Verifier si on la deja avant de l'ecrire
                global nameCert
                file = open(directory + '/' + str(nameCert) + ".cer", "w")
                file.write(str(packet[X509Cert]))
                file.close()
                nameCert += 1

if __name__ == "__main__":
    find()