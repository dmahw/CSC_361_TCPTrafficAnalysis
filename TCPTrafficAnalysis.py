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
    RTT = 0
    minRTT = -1
    meanRTT = -1
    maxRTT = -1
    pktCount = 0
    minPacket = 0
    meanPacket = 0
    maxPacket = 0
    window = 0
    minWindow = -1
    meanWindow = -1
    maxWindow = -1

    def printStats(self):
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("Global Statistics:")
        print("Global Connection Count: " + str(self.connCount))
        print("RST Connection Count: " + str(self.rstCount))
        print("Open Connection Count: " + str(self.openCount))
        print("Closed Connection Count: " + str(self.closeCount))
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("Duration: " + str(self.duration))
        print("Minimum Connection Duration: " + str(self.minDuration))
        print("Mean Connection Duration: " + str(self.meanDuration))
        print("Max Connection Duration: " + str(self.maxDuration))
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("RTT: " + str(self.RTT))
        print("Minimum RTT: " + str(self.minRTT))
        print("Mean RTT: " + str(self.meanRTT))
        print("Max RTT: " + str(self.maxRTT))
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("Packet Count: " + str(self.pktCount))
        print("Minimum Packets Sent: " + str(self.minPacket))
        print("Mean Packets Sent: " + str(self.meanPacket))
        print("Max Packets Sent: " + str(self.maxPacket))
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("Window Size: " + str(self.window))
        print("Minimum Window Size: " + str(self.minWindow))
        print("Mean Window Size: " + str(self.meanWindow))
        print("Max Window Size: " + str(self.maxWindow))

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
        self.pastClientSeq = packet.seq + 1
        self.pastServerSeq = 0
        self.pastPacketTime = packet.time

        self.duration = 0
        self.RTT = 0 
        self.minRTT = -1
        self.meanRTT = -1
        self.maxRTT = -1
        self.window = 0
        self.minWindow = -1
        self.meanWindow = -1
        self.maxWindow = -1

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
            print("Status: " + str(link.status))
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

def updateWindowSizeConnection(connection, packet):
    connection.window = connection.window + packet.windowSize
    if connection.minWindow == -1:
        connection.minWindow = packet.windowSize
    if connection.maxWindow == -1:
        connection.maxWindow = packet.windowSize
    if packet.windowSize <= connection.minWindow:
        connection.minWindow = packet.windowSize
    if packet.windowSize >= connection.maxWindow:
        connection.maxWindow = packet.windowSize
    return 1

def updateRTTConnection(connection, packet):
    if connection.pastClientSeq == packet.ack or connection.pastServerSeq == packet.ack:
        connection.RTT = connection.RTT + packet.time - connection.pastPacketTime
        if connection.minRTT == -1:
            connection.minRTT = packet.time - connection.pastPacketTime
        if connection.maxRTT == -1:
            connection.maxRTT = packet.time - connection.pastPacketTime
        if connection.minRTT <= packet.time - connection.pastPacketTime:
            connection.minRTT = packet.time - connection.pastPacketTime
        if connection.maxRTT >= packet.time - connection.pastPacketTime:
            connection.maxRTT = packet.time - connection.pastPacketTime
    return 1

def updateDstSrcCount(connection, packet):
    connection.packetCount = connection.packetCount + 1
    connection.srcDstPacketCount = connection.srcDstPacketCount + 1
    if (packet.ack - connection.pastServerSeq >= 0):
        connection.dstSrcByteCount = connection.dstSrcByteCount + packet.ack - connection.pastServerSeq
        connection.pastClientSeq = packet.seq
        connection.byteCount = connection.byteCount + packet.ack - connection.pastServerSeq
    connection.dstSrcByteCount = packet.ack - connection.initialServerSeq
    connection.byteCount = connection.srcDstByteCount + connection.dstSrcByteCount
    return 1

def updateSrcDstCount(connection, packet):
    connection.packetCount = connection.packetCount + 1
    connection.dstSrcPacketCount = connection.dstSrcPacketCount + 1
    if (packet.ack - connection.pastClientSeq >= 0):
        if connection.initialServerSeq == 0:
            connection.initialServerSeq = packet.seq + 2
            connection.pastServerSeq = packet.seq + 1
        else:
            connection.srcDstByteCount = connection.srcDstByteCount + packet.ack - connection.pastClientSeq
            connection.pastServerSeq = packet.seq
            connection.byteCount = connection.byteCount + packet.ack - connection.pastClientSeq
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
    print("Minimum RTT values including both send/received: " + str(stats.minRTT))
    print("Mean RTT values including both send/received: " + str(stats.meanRTT))
    print("Maximum RTT values including both send/received: " + str(stats.maxRTT))
    print("")
    print("Minimum number of packets including both send/received: " + str(stats.minPacket))
    print("Mean number of packets including both send/received: " + str(stats.meanPacket))
    print("Maximum number of packets including both send/received: " + str(stats.maxPacket))
    print("")
    print("Minimum receive window sizes including both send/received: " + str(stats.minWindow))
    print("Mean receive window sizes including both send/received: " + str(stats.meanWindow))
    print("Maximum receive window sizes including both send/receive: " + str(stats.maxWindow))
    print("___________________________________________________________________________________")

def checkForNewConnection(stats, connections, packet):
    if "SYN" in packet.flags:
        print(packet.flags)
        for connection in connections.links:
            if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
                connection.status[0] = connection.status[0] + 1
                return 0
            if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
                connection.status[0] = connection.status[0] + 1
                return 0
        connection = Connection(packet)
        connection.srcDstPacketCount = connection.srcDstPacketCount + 1
        connection.packetCount = connection.packetCount + 1
        connection.status[0] = connection.status[0] + 1
        stats.openCount = stats.openCount + 1
        stats.connCount = stats.connCount + 1

        updateWindowSizeConnection(connection, packet)
        updateRTTConnection(connection, packet)

        connections.add(connection)
        return 1
    return 0

def checkForExistingConnection(stats, connections, packet):
    isConnection = 0
    for connection in connections.links:
        if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
            connection.endTime = packet.time

            updateWindowSizeConnection(connection, packet)
            updateRTTConnection(connection, packet)
            updateDstSrcCount(connection, packet)

            return 1
            
        if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
            connection.endTime = packet.time

            updateWindowSizeConnection(connection, packet)
            updateRTTConnection(connection, packet)
            updateSrcDstCount(connection, packet)

            return 1
    return 0

def checkForRST(stats, connections, packet):
    if "RST" in packet.flags:
        for connection in connections.links:
            if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
                connection.status[2] = connection.status[2] + 1
                connection.endTime = packet.time

                updateWindowSizeConnection(connection, packet)
                updateRTTConnection(connection, packet)
                updateDstSrcCount(connection, packet)

                return 1
            if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
                connection.status[2] = connection.status[2] + 1
                connection.endTime = packet.time

                updateWindowSizeConnection(connection, packet)
                updateRTTConnection(connection, packet)
                updateSrcDstCount(connection, packet)

                return 1
    return 0   

def checkForFIN(stats, connections, packet):
    if "FIN" in packet.flags:
        for connection in connections.links:
            if (connection.srcAdd == packet.srcIP) and (connection.dstAdd == packet.dstIP) and (connection.srcPort == packet.srcPort) and (connection.dstPort == packet.dstPort):
                connection.status[1] = connection.status[1] + 1
                connection.endTime = packet.time

                updateWindowSizeConnection(connection, packet)
                updateRTTConnection(connection, packet)
                updateDstSrcCount(connection, packet)

                return 1
            if (connection.dstAdd == packet.srcIP) and (connection.srcAdd == packet.dstIP) and (connection.dstPort == packet.srcPort) and (connection.srcPort == packet.dstPort):
                connection.status[1] = connection.status[1] + 1
                connection.endTime = packet.time

                updateWindowSizeConnection(connection, packet)
                updateRTTConnection(connection, packet)
                updateSrcDstCount(connection, packet)
                
                return 1
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

                stats.window = stats.window + connection.window
                if stats.minWindow == -1:
                    stats.minWindow = connection.minWindow
                if stats.maxWindow == -1:
                    stats.maxWindow = connection.maxWindow
                if connection.minWindow <= stats.minWindow:
                    stats.minWindow = connection.minWindow
                if connection.maxWindow >= stats.maxWindow:
                    stats.maxWindow = connection.maxWindow 

                stats.RTT = stats.RTT + connection.RTT
                if stats.minRTT == -1:
                    stats.minRTT = connection.minRTT
                if stats.maxRTT == -1:
                    stats.maxRTT = connection.maxRTT
                if connection.minRTT <= stats.minRTT:
                    stats.minRTT = connection.minRTT
                if connection.maxRTT >= stats.maxRTT:
                    stats.maxRTT = connection.maxRTT 
            
            if connection.status[2] >= 1:
                stats.rstCount = stats.rstCount + 1

    stats.meanDuration = stats.duration / stats.closeCount
    stats.meanPacket = stats.pktCount / stats.closeCount
    stats.meanWindow = stats.window / stats.pktCount
    stats.meanRTT = stats.RTT / stats.pktCount
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

        # printPacket(packet)
        # print("++++++++++++++++++++++++++++++++++++++++++++++++")
        if checkForNewConnection(stats, connections, packet) == 0:
            if checkForRST(stats, connections, packet) == 0:
                if checkForFIN(stats, connections, packet) == 0:
                    if checkForExistingConnection(stats, connections, packet) == 0:
                        print("ERROR")
                        exit(1)
        del packet
    
    finalStatCheck(stats, connections)
    # connections.printConnections()
    # stats.printStats()
    printFinal(stats, connections)

main()


# Parsing is taken from the link below, in particluar the mac_addr, and inet_to_str. 
# Opening the file, and obtaining the buffer and timestamp is from
# http://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html?highlight=print%20ip