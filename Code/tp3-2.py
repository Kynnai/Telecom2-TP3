from scapy.all import *
#from scapy.layers.ssl_tls import *
import socket

fichPCAP = "trace7.pcap"
nameCert = 1


def find():
    file = open("test1111.txt", "w")
    for packet in rdpcap(fichPCAP):
        if packet.haslayer(SSL):
            print(str(packet[3][1]))
            #directory = str(packet[IP].src)
            #if not os.path.exists(directory):
             #   os.makedirs(directory)

            # TODO: Verifier si on la deja avant de l'ecrire
            #global nameCert
            #file = open(directory + '/' + str(nameCert) + ".cer", "w")
            #file.write(str(packet[3]))
            #file.close()
            #nameCert += 1

if __name__ == "__main__":
    find()