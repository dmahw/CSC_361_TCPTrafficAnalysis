import sys, dpkt, socket
from dpkt.compat import compat_ord

VERBOSE = 1

class Statistics:
    rstCount = 0
    openCount = 0
    closeCount = 0
    minDuration = 0
    meanDuration = 0
    maxDuration = 0
    minRTT = 0
    meanRTT = 0
    maxRTT = 0
    minPacket = 0
    meanPacket = 0
    maxPacket = 0
    minWindow = 0
    meanWindow = 0
    maxWindow = 0

class Packet(object):
    srcMac = ""
    dstMac = ""
    srcIP = ""
    dstIP = ""
    IPLen = -1
    id = -1
    seq = -1
    ack = -1
    windowSize = -1
    flagsBin = -1
    flags = []
    srcPort = -1
    dstPort = -1
    time = -1

class Connection:
    def __init__(self, packet):
        self.srcAdd = packet.srcIP
        self.dstAdd = packet.dstIP
        self.srcPort = packet.srcPort
        self.dstPort = packet.dstPort
        self.status = ""
        self.startTime = packet.time
        self.endTime = -1
        self.duration = -1
        self.srcDstPacketCount = 0
        self.dstSrcPacketCount = 0
        self.packetCount = 0
        self.srcDstByteCount = 0
        self.dstSrcByteCount = 0
        self.byteCount = 0
        self.initialSeq = packet.seq

class Connections:
    def __init__(self):
        self.links = []
        self.size = 0

    def add(self, connection):
        self.links.append(connection)
        self.size = self.size + 1

    def printConnections(self):
        count = 1
        for link in self.links:
            print("Connection " + str(count) + ":")
            print("Source Address: " + link.srcAdd)
            print("Destination Address: " + link.dstAdd)
            print("Source Port: " + str(link.srcPort))
            print("Destination Port: " + str(link.dstPort))
            print("Status: " + link.status)
            print("Start Time: " + str(link.startTime))
            print("End Time: " + str(link.endTime))
            print("Duration: " + str(link.duration))
            print("Number of packets send from Source to Destination: " + str(link.srcDstPacketCount))
            print("Number of packets send from Destination to Source: " + str(link.dstSrcPacketCount))
            print("Total number of packets: " + str(link.packetCount))
            print("Number of data bytes send from Source to Destination: " + str(link.srcDstByteCount))
            print("Number of data bytes send from Destination to Source: " + str(link.dstSrcByteCount))
            print("Total number of data bytes: " + str(link.byteCount))
            count = count + 1
            if count <= (self.size): print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

def printPacket(packet):
    print("Source MAC: " + packet.srcMac)
    print("Destination MAC: " + packet.dstMac)
    print("Source IP: " + packet.srcIP)
    print("Destination IP: " + packet.dstIP)
    print("IP Header Length: " + str(packet.IPLen))
    print("Packet ID: " + str(packet.id))
    print("Sequence: " + str(packet.seq))
    print("Acknowledgement: " + str(packet.ack))
    print("Window Size: " + str(packet.windowSize))
    print("Flag Binary: " + bin(packet.flagsBin))
    print("Flags: " + str(packet.flags))
    print("Source Port: " + str(packet.srcPort))
    print("Destination Port: " + str(packet.dstPort))
    print("Time: " + str(packet.time))

def mac_addr(address):
    return ":".join("%02x" % compat_ord(b) for b in address)

def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)

def binToFlags(packet):
    packet.flags = []
    if packet.flagsBin & 0b1: packet.flags.append("FIN")
    if packet.flagsBin & 0b10: packet.flags.append("SYN")
    if packet.flagsBin & 0b100: packet.flags.append("RST")
    if packet.flagsBin & 0b1000: packet.flags.append("PSH")
    if packet.flagsBin & 0b10000: packet.flags.append("ACK")
    if packet.flagsBin & 0b100000: packet.flags.append("URG")
    return packet

def checkForNewConnection(connections, packet):
    if "SYN" in packet.flags:
        isNew = 1
        for connection in connections.links:
            if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
                isNew = 0
                break
            if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
                isNew = 0
                break
        if isNew:
            connection = Connection(packet)
            connections.add(connection)

def checkForExistingConnection(connections, packet):
    if "ACK" in packet.flags:
        for connection in connections.links:
            isNew = 1
            if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
                connection.packetCount = conenction.packetCount + 1
                connection
                isNew = 0
                break
            if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
                isNew = 0
                break          
        

def main():
    traceFileName = sys.argv[1]

    traceFile = open(traceFileName, "rb")
    tracePcap = dpkt.pcap.Reader(traceFile)

    stats = Statistics()
    connections = Connections()
    count = 0

    for timeStamp, buf in tracePcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        packet = Packet()
        packet.srcMac = mac_addr(eth.src)
        packet.dstMac = mac_addr(eth.dst)
        
        packet.srcIP = inet_to_str(ip.src)
        packet.dstIP = inet_to_str(ip.dst)
        packet.IPLen = ip.len
        packet.id = ip.id
        
        packet.seq = tcp.seq
        packet.ack = tcp.ack
        packet.windowSize = tcp.win
        packet.flagsBin = tcp.flags
        packet.srcPort = tcp.sport
        packet.dstPort = tcp.dport
        packet.time = timeStamp
        packet = binToFlags(packet)

        # printPacket(packet)
        checkForNewConnection(connections, packet)
        
        del packet

        count = count + 1
        if count >= 3:
            break
    connections.printConnections()

main()


# Parsing is taken from the link below, in particluar the mac_addr, and inet_to_str. 
# Opening the file, and obtaining the buffer and timestamp is from
# http://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html?highlight=print%20ip