import pcapy, sys, dpkt, socket
from dpkt.compat import compat_ord

VERBOSE = 1

# Printing mac_addresses
# http://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html?highlight=print%20ip
def mac_addr(address):
    return ":".join("%02x" % compat_ord(b) for b in address)

def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)

def main():
    traceFileName = sys.argv[1]

    traceFile = open(traceFileName, "rb")
    tracePcap = dpkt.pcap.Reader(traceFile)

    for timeStamp, buf in tracePcap:
        eth = dpkt.ethernet.Ethernet(buf)
        head = eth.data
        print(mac_addr(eth.src))
        print(inet_to_str(head.src))
        print(head.sport)
        break

main()