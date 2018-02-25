import sys, dpkt, socket
from dpkt.compat import compat_ord

VERBOSE = 1

class Statistics:
    connCount = 0
    rstCount = 0
    openCount = 0
    closeCount = 0
    duration = 0
    minDuration = 0
    meanDuration = 0
    maxDuration = 0
    RTTCount = 0
    RTT = []
    minRTT = -1
    meanRTT = -1
    maxRTT = -1
    pktCount = 0
    minPacket = 0
    meanPacket = 0
    maxPacket = 0
    window = []
    minWindow = -1
    meanWindow = -1
    maxWindow = -1

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
        self.status = [0, 0, 0]
        self.startTime = packet.time
        self.endTime = packet.time
        self.srcDstPacketCount = 0
        self.dstSrcPacketCount = 0
        self.packetCount = 0
        self.srcDstByteCount = 0
        self.dstSrcByteCount = 0
        self.byteCount = 0
        self.initialClientSeq = packet.seq + 1
        self.initialServerSeq = 0
        self.pastClientSeq = -50
        self.pastServerSeq = 0
        self.pastClientPacketTime = packet.time
        self.pastServerPacketTime = 0
        self.RTTCount = 0

        self.duration = 0
        self.RTT = []
        self.window = []

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
            print("Status: " + "S" + str(link.status[0]) + "F" + str(link.status[1]) + "R" + str(link.status[2]))
            if link.status[0] >= 1:
                if link.status[1] >= 1:
                    print("Start Time: " + str(link.startTime))
                    print("End Time: " + str(link.endTime))
                    print("Duration: " + str(link.duration))
                    print("Number of packets send from Source to Destination: " + str(link.srcDstPacketCount))
                    print("Number of packets send from Destination to Source: " + str(link.dstSrcPacketCount))
                    print("Total number of packets: " + str(link.packetCount))
                    print("Number of data bytes send from Source to Destination: " + str(link.srcDstByteCount))
                    print("Number of data bytes send from Destination to Source: " + str(link.dstSrcByteCount))
                    print("Total number of data bytes: " + str(link.byteCount))
                    print("END")
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

def mac_addr(address):      #Refer to Reference
    return ":".join("%02x" % compat_ord(b) for b in address)

def inet_to_str(inet):      #Refer to Reference
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


def clientInitialRTT(stats, connection, packet):
    connection.pastClientSeq = packet.seq
    connection.pastClientPacketTime = packet.time
    return 0

def clientFinalRTT(stats, connection, packet):
    if connection.pastClientSeq <= packet.ack:
        RTT = packet.time - connection.pastClientPacketTime
        connection.RTT.append(RTT)
    return 0

def serverInitialRTT(stats, connection, packet):
    connection.pastServerSeq = packet.seq
    connection.pastServerPacketTime = packet.time
    return 0

def serverFinalRTT(stats, connection, packet):
    if connection.pastServerSeq <= packet.ack:
        RTT = packet.time - connection.pastServerPacketTime
        connection.RTT.append(RTT)
    return 0

def updateDstSrcCount(connection, packet):
    connection.packetCount = connection.packetCount + 1
    connection.srcDstPacketCount = connection.srcDstPacketCount + 1
    connection.dstSrcByteCount = packet.ack - connection.initialServerSeq - 1
    connection.byteCount = connection.srcDstByteCount + connection.dstSrcByteCount
    return 1

def updateSrcDstCount(connection, packet):
    connection.packetCount = connection.packetCount + 1
    connection.dstSrcPacketCount = connection.dstSrcPacketCount + 1
    if connection.initialServerSeq == 0:
        connection.initialServerSeq = packet.seq + 1
    connection.srcDstByteCount = packet.ack - connection.initialClientSeq
    connection.byteCount = connection.srcDstByteCount + connection.dstSrcByteCount
    return 1

def printFinal(stats, connections):
    print("A) Total number of connections: " + str(connections.size))
    print("___________________________________________________________________________________")
    print("")
    print("B) Connection's details:")
    print("")
    connections.printConnections()
    print("___________________________________________________________________________________")
    print("")
    print("C) General:")
    print("")
    print("Total number of complete TCP connections: " + str(stats.closeCount))
    print("Number of reset TCP connections: " + str(stats.rstCount))
    print("Number of TCP connections that were still open when the trace capture ended: " + str(stats.openCount))
    print("___________________________________________________________________________________")
    print("")
    print("D) Complete TCP connections:")
    print("")
    print("Minimum time durations: " + str(stats.minDuration))
    print("Mean time durations: " + str(stats.meanDuration))
    print("Maximum time duration: " + str(stats.maxDuration))
    print("")
    print("Minimum RTT values: " + str(stats.minRTT))
    print("Mean RTT values: " + str(stats.meanRTT))
    print("Maximum RTT values: " + str(stats.maxRTT))
    print("")
    print("Minimum number of packets including both send/received: " + str(stats.minPacket))
    print("Mean number of packets including both send/received: " + str(stats.meanPacket))
    print("Maximum number of packets including both send/received: " + str(stats.maxPacket))
    print("")
    print("Minimum receive window sizes including both send/received: " + str(stats.minWindow))
    print("Mean receive window sizes including both send/received: " + str(stats.meanWindow))
    print("Maximum receive window sizes including both send/receive: " + str(stats.maxWindow))
    print("___________________________________________________________________________________")


def analyzePacket(stats, connections, packet):
    for connection in connections.links:
        if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
            if "SYN" in packet.flags:
                connection.status[0] = connection.status[0] + 1
            if "FIN" in packet.flags:
                connection.status[1] = connection.status[1] + 1
                connection.endTime = packet.time
            if "RST" in packet.flags:
                connection.status[2] = connection.status[2] + 1
            
            clientInitialRTT(stats, connection, packet)
            serverFinalRTT(stats, connection, packet)

            connection.window.append(packet.windowSize)
            updateDstSrcCount(connection, packet)
            
            return 1

        if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
            if "SYN" in packet.flags:
                connection.status[0] = connection.status[0] + 1
            if "FIN" in packet.flags:
                connection.status[1] = connection.status[1] + 1
                connection.endTime = packet.time
            if "RST" in packet.flags:
                connection.status[2] = connection.status[2] + 1

            serverInitialRTT(stats, connection, packet)
            clientFinalRTT(stats, connection, packet)

            connection.window.append(packet.windowSize)
            updateSrcDstCount(connection, packet)
            return 1

    connection = Connection(packet)
    connection.srcDstPacketCount = connection.srcDstPacketCount + 1
    connection.packetCount = connection.packetCount + 1
    connection.status[0] = connection.status[0] + 1
    stats.openCount = stats.openCount + 1
    stats.connCount = stats.connCount + 1
    connection.window.append(packet.windowSize)
    connections.add(connection)
    return 0

def finalStatCheck(stats, connections):
    for connection in connections.links:
        if connection.status[0] >= 1:
            if connection.status[1] >= 1:
                stats.openCount = stats.openCount - 1
                stats.closeCount = stats.closeCount + 1

                connection.duration = connection.endTime - connection.startTime
                stats.duration = stats.duration + connection.duration
                if stats.minDuration == 0:
                    stats.minDuration = connection.duration
                if stats.maxDuration == 0:
                    stats.maxDuration = connection.duration
                if connection.duration <= stats.minDuration:
                    stats.minDuration = connection.duration
                if connection.duration >= stats.maxDuration:
                    stats.maxDuration = connection.duration
                
                stats.pktCount = stats.pktCount + connection.packetCount
                if stats.minPacket == 0:
                    stats.minPacket = connection.packetCount
                if stats.maxPacket == 0:
                    stats.maxPacket = connection.packetCount
                if connection.packetCount <= stats.minPacket:
                    stats.minPacket = connection.packetCount
                if connection.packetCount >= stats.maxPacket:
                    stats.maxPacket = connection.packetCount

                stats.window.extend(connection.window)

                stats.RTT.extend(connection.RTT)

            if connection.status[2] >= 1:
                stats.rstCount = stats.rstCount + 1

    stats.meanDuration = stats.duration / stats.closeCount
    stats.meanPacket = stats.pktCount / stats.closeCount

    stats.minWindow = min(stats.window)
    stats.maxWindow = max(stats.window)
    stats.meanWindow = sum(stats.window)/stats.pktCount

    stats.minRTT = min(stats.RTT)
    stats.maxRTT = max(stats.RTT)
    stats.meanRTT = sum(stats.RTT) / len(stats.RTT)
    
    return 1

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

        analyzePacket(stats, connections, packet)
        del packet
    
    finalStatCheck(stats, connections)
    printFinal(stats, connections)

main()


# Parsing is taken from the link below, in particluar the mac_addr, and inet_to_str. 
# Opening the file, and obtaining the buffer and timestamp is from
# http://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html?highlight=print%20ip