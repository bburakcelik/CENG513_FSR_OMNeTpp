/*
 * Fsr.cc
 * Fisheye State Routing Protocol Implementation
 */

#include "inet/routing/fsr/Fsr.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/common/packet/chunk/BytesChunk.h"

namespace inet {
namespace fsr {

Define_Module(Fsr);

Fsr::Fsr()
{
    helloBroadcastTimer = nullptr;
    lspUpdateTimer = nullptr;
    decrementAgeTimer = nullptr;
    lspLifeTimeTimer = nullptr;
    testTimer = nullptr;
    routingTable = nullptr;
    interfaceTable = nullptr;
    sequenceNumber = 0;
    controlBytesSent = 0;
    numLSPsSent = 0;
    numLSPsReceived = 0;
    numHellosSent = 0;
    numPacketsReceived = 0;
}

Fsr::~Fsr()
{
    cancelAndDelete(helloBroadcastTimer);
    cancelAndDelete(lspUpdateTimer);
    cancelAndDelete(decrementAgeTimer);
    cancelAndDelete(lspLifeTimeTimer);
    cancelAndDelete(testTimer);

    // Cancel neighbor timeout timers
    for (auto &entry : neighborTimeouts) {
        cancelAndDelete(entry.second);
    }
    neighborTimeouts.clear();
}

void Fsr::initialize(int stage)
{
    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        EV_INFO << "=== INITSTAGE_LOCAL @ " << simTime() << " ===" << endl;
        // Read parameters
        helloBroadcastInterval = par("helloBroadcastInterval");
        lspUpdateInterval = par("lspUpdateInterval");
        maxWaitTimeForLspAnnouncement = par("maxWaitTimeForLspAnnouncement");
        maxJitter = par("maxJitter");
        lspLifeTimeInterval = par("lspLifeTimeInterval");
        lifeTime = par("lifeTime");

        if (hasPar("fsrPort")) {
            fsrPort = par("fsrPort");
        } else {
            EV_ERROR << "fsrPort parameter NOT FOUND! Using default 6543" << endl;
            fsrPort = 6543; // Default port
        }

        EV_INFO << "Node: " << getContainingNode(this)->getFullName() << " | FSR Parameters:" << endl;
        EV_INFO << "  helloBroadcastInterval: " << helloBroadcastInterval << "s" << endl;
        EV_INFO << "  lspUpdateInterval: " << lspUpdateInterval << "s" << endl;
        EV_INFO << "  fsrPort: " << fsrPort << endl;

        // Initialize timers (create them, don't schedule yet)
        helloBroadcastTimer = new cMessage("helloBroadcastTimer");
        lspUpdateTimer = new cMessage("lspUpdateTimer");
        decrementAgeTimer = new cMessage("decrementAgeTimer");
        lspLifeTimeTimer = new cMessage("lspLifeTimeTimer");
        testTimer = new cMessage("testTimer"); // If you still have this for debugging

        // Initialize statistics
        WATCH(numLSPsSent);
        WATCH(numLSPsReceived);
        WATCH(numHellosSent);
        WATCH(numPacketsReceived);
        WATCH(controlBytesSent);

        socketInitialized = false; // Ensure flag is reset at the beginning
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        EV_INFO << "=== INITSTAGE_ROUTING_PROTOCOLS @ " << simTime() << " ===" << endl;

        if (!socketInitialized) {
            EV_INFO << "Performing one-time socket and network interface setup." << endl;
            host = findContainingNode(this);
            if (!host) {
                throw cRuntimeError("Host module not found for FSR");
            }
            EV_INFO << "Host module: " << host->getFullPath() << endl;

            try {
                cModule *ipv4Module = host->getSubmodule("ipv4");
                if (!ipv4Module) throw cRuntimeError("IPv4 module not found in host");

                cModule *rtModule = ipv4Module->getSubmodule("routingTable");
                if (!rtModule) throw cRuntimeError("RoutingTable module not found in IPv4 module");
                routingTable = check_and_cast<IRoutingTable*>(rtModule);
                // To get full path, cast to cModule*
                EV_INFO << "Routing table module acquired: " << (dynamic_cast<cModule*>(routingTable) ? dynamic_cast<cModule*>(routingTable)->getFullPath().c_str() : "N/A") << endl;


                cModule *iftModule = host->getSubmodule("interfaceTable");
                if (!iftModule) throw cRuntimeError("InterfaceTable module not found in host");
                interfaceTable = check_and_cast<IInterfaceTable*>(iftModule);
                EV_INFO << "Interface table module acquired: " << (dynamic_cast<cModule*>(interfaceTable) ? dynamic_cast<cModule*>(interfaceTable)->getFullPath().c_str() : "N/A") << endl;


            } catch (const std::exception &e) {
                throw cRuntimeError("Failed to get module references: %s", e.what());
            }

            if (!routingTable) throw cRuntimeError("RoutingTable pointer is null after attempting to acquire");
            if (!interfaceTable) throw cRuntimeError("InterfaceTable pointer is null after attempting to acquire");

            selfAddress = getRouterId(); // Helper function to get node's IP
            EV_INFO << "Self IP Address determined: " << selfAddress << endl;

            if (selfAddress.isUnspecified()) {
                EV_ERROR << "CRITICAL: Could not determine node IP address! FSR may not function correctly." << endl;
            }

            // Determine primary broadcast address and output interface ID
            primaryBroadcastAddress = Ipv4Address::ALLONES_ADDRESS; // Default
            outputInterfaceId = -1; // Default
            bool broadcastAddrFound = false;

            if (!selfAddress.isUnspecified() && interfaceTable) {
                for (int i = 0; i < interfaceTable->getNumInterfaces(); ++i) {
                    NetworkInterface *ie = interfaceTable->getInterface(i);
                    if (ie && ie->isUp() && !ie->isLoopback() && ie->isBroadcast()) {
                        auto ipv4Data = ie->getProtocolData<Ipv4InterfaceData>();
                        if (ipv4Data && !ipv4Data->getIPAddress().isUnspecified() && !ipv4Data->getNetmask().isUnspecified()) {
                            Ipv4Address interfaceIp = ipv4Data->getIPAddress();
                            Ipv4Address netmask = ipv4Data->getNetmask();
                            uint32_t network_addr_int = interfaceIp.getInt() & netmask.getInt();
                            uint32_t broadcast_addr_int = network_addr_int | ~netmask.getInt();
                            Ipv4Address calculatedBroadcastAddr = Ipv4Address(broadcast_addr_int);

                            EV_DEBUG << "Interface " << ie->getInterfaceName() << " (ID: " << ie->getInterfaceId()
                                     << ", IP: " << interfaceIp << ", Netmask: " << netmask
                                     << ") - Calculated broadcast: " << calculatedBroadcastAddr << endl;

                            if (interfaceIp == selfAddress || !broadcastAddrFound) {
                                primaryBroadcastAddress = calculatedBroadcastAddr;
                                outputInterfaceId = ie->getInterfaceId();
                                EV_INFO << "Selected broadcast address: " << primaryBroadcastAddress
                                          << " from interface " << ie->getInterfaceName() << " (ID: " << outputInterfaceId << ")" << endl;
                                broadcastAddrFound = true;
                                if (interfaceIp == selfAddress) {
                                    break; // Prefer the interface matching selfAddress
                                }
                            }
                        }
                    }
                }
            }
            if (!broadcastAddrFound && !selfAddress.isUnspecified()) {
                EV_WARN << "Could not dynamically determine subnet broadcast address for " << selfAddress
                        << ". Using " << primaryBroadcastAddress << ". Check network config if broadcasts fail." << endl;
            } else if (selfAddress.isUnspecified()) {
                EV_WARN << "Self IP is unspecified, cannot determine subnet broadcast. Using " << primaryBroadcastAddress << "." << endl;
            }


            // Initialize UDP Socket
            socket.setOutputGate(gate("socketOut"));
            socket.setCallback(this);
            socket.setReuseAddress(true); // Allow reusing address, good for quick restarts

            // Enable broadcasting on the socket using the INET UdpSocket API
            socket.setBroadcast(true);
            EV_INFO << "Called UDP socket.setBroadcast(true) to enable broadcasting." << endl;


            // Bind the socket
            if (!selfAddress.isUnspecified()) {
                socket.bind(selfAddress, fsrPort);
                EV_INFO << "FSR UDP socket bound to " << selfAddress << ":" << fsrPort << endl;
            } else {
                // Fallback if selfAddress couldn't be determined (less ideal for specific broadcast interface selection)
                socket.bind(fsrPort);
                EV_WARN << "FSR UDP socket bound to port " << fsrPort << " on all available interfaces (selfAddress was unspecified)." << endl;
            }
            EV_INFO << "Socket output gate set to: " << gate("socketOut")->getFullPath() << endl;

            socketInitialized = true; // Mark socket as initialized
        } else {
            EV_INFO << "Socket and network interface setup already performed, skipping in this stage." << endl;
        }

        // These can be logged multiple times if useful, or moved inside the flag if not.
        logInterfaceInfo();
        logUdpActivity();
        EV_INFO << "********************************************" << endl;
    }
    else if (stage == INITSTAGE_LAST) {
        EV_INFO << "=== INITSTAGE_LAST @ " << simTime() << " ===" << endl;
        if (!socketInitialized) {
             EV_ERROR << "CRITICAL: Socket was not initialized by INITSTAGE_ROUTING_PROTOCOLS. FSR will likely fail." << endl;
        }

        initNode(); // Initialize this node's entry in its own topology table

        logUdpActivity();
        logInterfaceInfo();
        logRoutingTableInfo(); // If you have this helper

        if (helloBroadcastTimer->isScheduled()) cancelEvent(helloBroadcastTimer);
        scheduleAt(simTime() + uniform(0, maxJitter), helloBroadcastTimer);

        if (lspUpdateTimer->isScheduled()) cancelEvent(lspUpdateTimer);
        scheduleAt(simTime() + lspUpdateInterval + uniform(0, maxJitter), lspUpdateTimer);

        if (decrementAgeTimer->isScheduled()) cancelEvent(decrementAgeTimer);
        scheduleAt(simTime() + 1.0, decrementAgeTimer);

        if (lspLifeTimeTimer->isScheduled()) cancelEvent(lspLifeTimeTimer);
        scheduleAt(simTime() + lspLifeTimeInterval, lspLifeTimeTimer);

        if (testTimer && testTimer->isScheduled()) cancelEvent(testTimer);
        if (testTimer) scheduleAt(simTime() + 5.0 + uniform(0,0.1), testTimer);

        EV_INFO << "FSR timers scheduled. Protocol operation starting." << endl;
    }
}

Ipv4Address Fsr::getRouterId()
{
    EV_INFO << "=== GETTING ROUTER ID ===" << endl;

    // Verify interface table is available
    if (!interfaceTable) {
        EV_ERROR << "Interface table is not available!" << endl;
        return Ipv4Address::UNSPECIFIED_ADDRESS;
    }

    // Get router ID from IPv4 routing table
    if (routingTable) {
        Ipv4RoutingTable *ipv4rt = dynamic_cast<Ipv4RoutingTable*>(routingTable);
        if (ipv4rt) {
            Ipv4Address routerId = ipv4rt->getRouterId();
            EV_INFO << "Router ID from routing table: " << routerId << endl;
            if (!routerId.isUnspecified()) {
                return routerId;
            }
        }
    }

    EV_INFO << "Checking interfaces..." << endl;
    EV_INFO << "Total interfaces: " << interfaceTable->getNumInterfaces() << endl;

    // Fallback: get from first non-loopback interface
    for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
        NetworkInterface *ie = interfaceTable->getInterface(i);
        EV_INFO << "Interface " << i << ": " << ie->getInterfaceName()
                << " (loopback=" << ie->isLoopback()
                << ", wireless=" << ie->isWireless() << ")" << endl;

        if (!ie->isLoopback() && ie->getProtocolData<Ipv4InterfaceData>()) {
            Ipv4Address addr = ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
            EV_INFO << "  IP address: " << addr << endl;
            if (!addr.isUnspecified()) {
                return addr;
            }
        }
    }

    EV_ERROR << "No valid IP address found!" << endl;
    return Ipv4Address::UNSPECIFIED_ADDRESS;
}

void Fsr::logUdpActivity()
{
    EV_INFO << "=== UDP SOCKET STATUS ===" << endl;
    EV_INFO << "Socket state: " << (socket.isOpen() ? "OPEN" : "CLOSED") << endl;
    EV_INFO << "Socket ID: " << socket.getSocketId() << endl;
    EV_INFO << "=========================" << endl;
}

void Fsr::logInterfaceInfo()
{
    EV_INFO << "=== INTERFACE INFORMATION ===" << endl;

    if (!interfaceTable) {
        EV_ERROR << "Interface table not available for logging!" << endl;
        return;
    }

    for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
        NetworkInterface *ie = interfaceTable->getInterface(i);
        EV_INFO << "Interface " << i << ":" << endl;
        EV_INFO << "  Name: " << ie->getInterfaceName() << endl;
        EV_INFO << "  Loopback: " << ie->isLoopback() << endl;
        EV_INFO << "  Wireless: " << ie->isWireless() << endl;
        EV_INFO << "  Broadcast: " << ie->isBroadcast() << endl;
        EV_INFO << "  Up: " << ie->isUp() << endl;

        if (ie->getProtocolData<Ipv4InterfaceData>()) {
            auto ipv4Data = ie->getProtocolData<Ipv4InterfaceData>();
            EV_INFO << "  IPv4 Address: " << ipv4Data->getIPAddress() << endl;
            EV_INFO << "  Netmask: " << ipv4Data->getNetmask() << endl;
        }
    }
    EV_INFO << "=============================" << endl;
}

void Fsr::logRoutingTableInfo()
{
    EV_INFO << "=== ROUTING TABLE ===" << endl;

    if (!routingTable) {
        EV_ERROR << "Routing table not available for logging!" << endl;
        return;
    }

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        EV_INFO << "Route " << i << ": ";
        EV_INFO << "dest=" << route->getDestinationAsGeneric();
        EV_INFO << " gw=" << route->getNextHopAsGeneric();
        EV_INFO << " iface=" << (route->getInterface() ? route->getInterface()->getInterfaceName() : "none");
        EV_INFO << endl;
    }
    EV_INFO << "=====================" << endl;
}

void Fsr::testDirectCommunication()
{
    EV_INFO << "=== TESTING DIRECT COMMUNICATION ===" << endl;

    // Find other FSR modules directly
    cModule *networkModule = getSimulation()->getSystemModule();
    for (cModule::SubmoduleIterator it(networkModule); !it.end(); ++it) {
        cModule *node = *it;
        if (node != host && node->getSubmodule("fsr")) {
            cModule *otherFsr = node->getSubmodule("fsr");
            EV_INFO << "Found other FSR module: " << otherFsr->getFullPath() << endl;
        }
    }
    EV_INFO << "====================================" << endl;
}

void Fsr::sendTestUdpPacket()
{
    EV_INFO << "=== SENDING TEST UDP PACKET ===" << endl;

    // Create a simple test packet
    Packet *testPkt = new Packet("TestUDP");
    auto testData = Ptr<BytesChunk>(new BytesChunk(std::vector<uint8_t>{0xAA, 0xBB, 0xCC, 0xDD}));
    testPkt->insertAtBack(testData);

    try {
        Ipv4Address bcast = Ipv4Address("10.0.0.255");
        socket.sendTo(testPkt, bcast, fsrPort);
        // socket.sendTo(testPkt, Ipv4Address::ALLONES_ADDRESS, fsrPort);
        EV_INFO << "Test UDP packet sent successfully!" << endl;
    } catch (const std::exception &e) {
        EV_ERROR << "Error sending test UDP packet: " << e.what() << endl;
        delete testPkt;
    }
    EV_INFO << "===============================" << endl;
}

void Fsr::handleStartOperation(LifecycleOperation *operation)
{
    EV_INFO << "=== FSR STARTING OPERATION ===" << endl;

    // Verify module references before proceeding
    if (!routingTable) {
        EV_ERROR << "Routing table not available in handleStartOperation!" << endl;
        return;
    }
    if (!interfaceTable) {
        EV_ERROR << "Interface table not available in handleStartOperation!" << endl;
        return;
    }

    initNode();

    // Log comprehensive system status
    logUdpActivity();
    logInterfaceInfo();
    logRoutingTableInfo();

    // Schedule test timer first
    scheduleAt(simTime() + 5.0, testTimer);

    // Schedule normal timers
    scheduleAt(simTime() + uniform(0, maxJitter), helloBroadcastTimer);
    scheduleAt(simTime() + lspUpdateInterval + uniform(0, maxJitter), lspUpdateTimer);
    scheduleAt(simTime() + 1.0, decrementAgeTimer);
    scheduleAt(simTime() + lspLifeTimeInterval, lspLifeTimeTimer);

    EV_INFO << "=== FSR STARTED ===" << endl;
}

void Fsr::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(helloBroadcastTimer);
    cancelEvent(lspUpdateTimer);
    cancelEvent(decrementAgeTimer);
    cancelEvent(lspLifeTimeTimer);
    cancelEvent(testTimer);

    // Cancel neighbor timeouts
    for (auto &entry : neighborTimeouts) {
        cancelAndDelete(entry.second);
    }
    neighborTimeouts.clear();

    clearRoutes();
    topologyTable.clear();
    neighbors.clear();
}

void Fsr::handleCrashOperation(LifecycleOperation *operation)
{
    handleStopOperation(operation);
}

void Fsr::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == helloBroadcastTimer) {
            sendHelloPacket();
            scheduleAt(simTime() + helloBroadcastInterval + uniform(-maxJitter, maxJitter), helloBroadcastTimer);
        }
        else if (msg == lspUpdateTimer) {
            sendTopologyUpdate();
            scheduleAt(simTime() + lspUpdateInterval + uniform(-maxJitter, maxJitter), lspUpdateTimer);
        }
        else if (msg == decrementAgeTimer) {
            decrementAge();
            scheduleAt(simTime() + 1.0, decrementAgeTimer);
        }
        else if (msg == lspLifeTimeTimer) {
            scheduleAt(simTime() + lspLifeTimeInterval, lspLifeTimeTimer);
        }
        else if (msg == testTimer) {
            testDirectCommunication();
            sendTestUdpPacket();

            // Log current statistics
            EV_INFO << "=== CURRENT STATISTICS ===" << endl;
            EV_INFO << "Packets sent: " << numHellosSent << endl;
            EV_INFO << "Packets received: " << numPacketsReceived << endl;
            EV_INFO << "Neighbors: " << neighbors.size() << endl;
            EV_INFO << "=========================" << endl;

            delete msg;
            return;
        }
        else {
            // Handle neighbor timeout
            for (auto it = neighborTimeouts.begin(); it != neighborTimeouts.end(); ++it) {
                if (it->second == msg) {
                    removeNeighbor(it->first);
                    neighborTimeouts.erase(it);
                    delete msg;
                    return;
                }
            }
        }
    } else {
        EV_INFO << "Received direct message: " << msg->getName() << endl;
        delete msg;
    }
}

void Fsr::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    numPacketsReceived++;

    EV_INFO << "##########################################" << endl;
    EV_INFO << "### FSR PACKET RECEIVED ###" << endl;
    EV_INFO << "Node: " << getContainingNode(this)->getFullName() << endl;
    EV_INFO << "My IP: " << selfAddress << endl;
    EV_INFO << "Total packets received so far: " << numPacketsReceived << endl;

    auto sourceAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    EV_INFO << "From: " << sourceAddr << endl;
    EV_INFO << "Packet size: " << packet->getTotalLength() << " bytes" << endl;
    EV_INFO << "Packet name: " << packet->getName() << endl;

    // Check if this is our test packet
    if (strcmp(packet->getName(), "TestUDP") == 0) {
        EV_INFO << "*** RECEIVED TEST UDP PACKET - UDP IS WORKING! ***" << endl;
        delete packet;
        EV_INFO << "##########################################" << endl;
        return;
    }

    // Check if packet contains FSR data
    if (packet->getTotalLength() < b(12)) { // Minimum FSR packet size is 12 bytes
        EV_WARN << "Packet too small to contain FSR data. Size: " << packet->getTotalLength() << " bytes. Expected at least 12." << endl;
        delete packet;
        return;
    }

    EV_INFO << "Packet size OK, attempting to extract bytes..." << endl;

    try {
        // Get the raw bytes from the packet
        auto bytesChunk = packet->peekDataAt<BytesChunk>(b(0), packet->getTotalLength());
        if (!bytesChunk) {
            EV_WARN << "Could not extract bytes from packet" << endl;
            delete packet;
            return;
        }

        EV_INFO << "Bytes extracted successfully, attempting deserialization..." << endl;

        // Print first few bytes for debugging
        const auto& bytes = bytesChunk->getBytes();
        EV_INFO << "First 10 bytes: ";
        for (size_t i = 0; i < std::min((size_t)10, bytes.size()); i++) {
            EV_INFO << (int)bytes[i] << " ";
        }
        EV_INFO << endl;

        // Deserialize the FSR packet from bytes
        auto fsrPacket = deserializeFsrPacket(bytesChunk);
        if (fsrPacket) {
            EV_INFO << "FSR packet deserialized successfully!" << endl;
            EV_INFO << "Packet type: " << fsrPacket->getPacketType() << endl;
            EV_INFO << "Source address: " << uint32ToIpv4(fsrPacket->getSourceAddress()) << endl;
            processFsrPacket(fsrPacket, sourceAddr);
        } else {
            EV_WARN << "Could not deserialize FSR packet" << endl;
        }
    }
    catch (const std::exception &e) {
        EV_ERROR << "Error processing FSR packet: " << e.what() << endl;
    }

    delete packet;
    EV_INFO << "### END FSR PACKET PROCESSING ###" << endl;
    EV_INFO << "##########################################" << endl;
}

void Fsr::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_ERROR << "*** UDP SOCKET ERROR ***" << endl;
    EV_ERROR << "Error: " << indication->str() << endl;
    EV_ERROR << "************************" << endl;
}

void Fsr::socketClosed(UdpSocket *socket)
{
    EV_ERROR << "*** UDP SOCKET CLOSED ***" << endl;
    EV_ERROR << "Socket was unexpectedly closed!" << endl;
    EV_ERROR << "************************" << endl;
}

Ptr<FsrPacket> Fsr::deserializeFsrPacket(const Ptr<const BytesChunk> &bytesChunk)
{
    const auto& bytes = bytesChunk->getBytes();
    if (bytes.size() < 11) { // Minimum packet size
        EV_ERROR << "Packet too small for deserialization" << endl;
        return nullptr;
    }

    size_t offset = 0;

    try {
        // Create new FSR packet
        Ptr<FsrPacket> fsrPacket(new FsrPacket());

        // Deserialize packet type (1 byte)
        uint8_t packetType = bytes[offset++];
        fsrPacket->setPacketType(packetType);

        // Deserialize source address (4 bytes) - store as uint32_t
        uint32_t srcAddr = 0;
        srcAddr |= ((uint32_t)bytes[offset++]) << 24;
        srcAddr |= ((uint32_t)bytes[offset++]) << 16;
        srcAddr |= ((uint32_t)bytes[offset++]) << 8;
        srcAddr |= ((uint32_t)bytes[offset++]);
        fsrPacket->setSourceAddress(srcAddr);

        // Deserialize sequence number (4 bytes)
        uint32_t seq = 0;
        seq |= ((uint32_t)bytes[offset++]) << 24;
        seq |= ((uint32_t)bytes[offset++]) << 16;
        seq |= ((uint32_t)bytes[offset++]) << 8;
        seq |= ((uint32_t)bytes[offset++]);
        fsrPacket->setSequenceNumber(seq);

        // Deserialize hop count (1 byte)
        uint8_t hopCount = bytes[offset++];
        fsrPacket->setHopCount(hopCount);

        // Set timestamp to current time (not transmitted)
        fsrPacket->setTimestamp(simTime().dbl());

        // Deserialize LSP entries count (2 bytes)
        if (offset + 2 > bytes.size()) {
            EV_ERROR << "Not enough bytes for entry count" << endl;
            return nullptr;
        }
        uint16_t entryCount = 0;
        entryCount |= ((uint16_t)bytes[offset++]) << 8;
        entryCount |= ((uint16_t)bytes[offset++]);

        fsrPacket->setLspEntriesArraySize(entryCount);

        // Deserialize LSP entries
        for (uint16_t i = 0; i < entryCount; i++) {
            if (offset + 6 > bytes.size()) {
                EV_ERROR << "Not enough bytes for LSP entry " << i << endl;
                return nullptr;
            }

            LspEntry entry;

            // Deserialize node address (4 bytes) - store as uint32_t
            uint32_t nodeAddr = 0;
            nodeAddr |= ((uint32_t)bytes[offset++]) << 24;
            nodeAddr |= ((uint32_t)bytes[offset++]) << 16;
            nodeAddr |= ((uint32_t)bytes[offset++]) << 8;
            nodeAddr |= ((uint32_t)bytes[offset++]);
            entry.setNodeAddress(nodeAddr);

            // Set sequence number
            entry.setSequenceNumber(seq);

            // Deserialize neighbors count (2 bytes)
            uint16_t neighborCount = 0;
            neighborCount |= ((uint16_t)bytes[offset++]) << 8;
            neighborCount |= ((uint16_t)bytes[offset++]);

            entry.setNeighborsArraySize(neighborCount);

            // Deserialize neighbors (4 bytes each) - store as uint32_t
            for (uint16_t j = 0; j < neighborCount; j++) {
                if (offset + 4 > bytes.size()) {
                    EV_ERROR << "Not enough bytes for neighbor " << j << " in entry " << i << endl;
                    return nullptr;
                }

                uint32_t neighborAddr = 0;
                neighborAddr |= ((uint32_t)bytes[offset++]) << 24;
                neighborAddr |= ((uint32_t)bytes[offset++]) << 16;
                neighborAddr |= ((uint32_t)bytes[offset++]) << 8;
                neighborAddr |= ((uint32_t)bytes[offset++]);
                entry.setNeighbors(j, neighborAddr);
            }

            fsrPacket->setLspEntries(i, entry);
        }

        EV_INFO << "Successfully deserialized FSR packet (type=" << (int)packetType
                << ", entries=" << entryCount << ", total bytes=" << bytes.size() << ")" << endl;

        return fsrPacket;
    }
    catch (const std::exception &e) {
        EV_ERROR << "Exception during deserialization: " << e.what() << endl;
        return nullptr;
    }
}

std::vector<uint8_t> Fsr::serializeFsrPacket(const Ptr<FsrPacket> &fsrPacket)
{
    std::vector<uint8_t> data;

    // Serialize packet type (1 byte)
    data.push_back((uint8_t)fsrPacket->getPacketType());

    // Serialize source address (4 bytes) - convert from uint32_t
    uint32_t srcAddr = fsrPacket->getSourceAddress();
    data.push_back((uint8_t)((srcAddr >> 24) & 0xFF));
    data.push_back((uint8_t)((srcAddr >> 16) & 0xFF));
    data.push_back((uint8_t)((srcAddr >> 8) & 0xFF));
    data.push_back((uint8_t)(srcAddr & 0xFF));

    // Serialize sequence number (4 bytes)
    uint32_t seq = fsrPacket->getSequenceNumber();
    data.push_back((uint8_t)((seq >> 24) & 0xFF));
    data.push_back((uint8_t)((seq >> 16) & 0xFF));
    data.push_back((uint8_t)((seq >> 8) & 0xFF));
    data.push_back((uint8_t)(seq & 0xFF));

    // Serialize hop count (1 byte)
    data.push_back((uint8_t)fsrPacket->getHopCount());

    // Serialize LSP entries count (2 bytes)
    uint16_t entryCount = fsrPacket->getLspEntriesArraySize();
    data.push_back((uint8_t)((entryCount >> 8) & 0xFF));
    data.push_back((uint8_t)(entryCount & 0xFF));

    // Serialize LSP entries
    for (unsigned int i = 0; i < entryCount; i++) {
        const LspEntry &entry = fsrPacket->getLspEntries(i);

        // Serialize node address (4 bytes) - already uint32_t
        uint32_t nodeAddr = entry.getNodeAddress();
        data.push_back((uint8_t)((nodeAddr >> 24) & 0xFF));
        data.push_back((uint8_t)((nodeAddr >> 16) & 0xFF));
        data.push_back((uint8_t)((nodeAddr >> 8) & 0xFF));
        data.push_back((uint8_t)(nodeAddr & 0xFF));

        // Serialize neighbors count (2 bytes)
        uint16_t neighborCount = entry.getNeighborsArraySize();
        data.push_back((uint8_t)((neighborCount >> 8) & 0xFF));
        data.push_back((uint8_t)(neighborCount & 0xFF));

        // Serialize neighbors (4 bytes each) - already uint32_t
        for (unsigned int j = 0; j < neighborCount; j++) {
            uint32_t neighborAddr = entry.getNeighbors(j);
            data.push_back((uint8_t)((neighborAddr >> 24) & 0xFF));
            data.push_back((uint8_t)((neighborAddr >> 16) & 0xFF));
            data.push_back((uint8_t)((neighborAddr >> 8) & 0xFF));
            data.push_back((uint8_t)(neighborAddr & 0xFF));
        }
    }

    return data;
}

void Fsr::processFsrPacket(const Ptr<const FsrPacket> &packet, const L3Address &sourceAddr)
{
    Ipv4Address src = sourceAddr.toIpv4();

    if (src == selfAddress) {
        EV_INFO << "Ignoring own packet from " << src << endl;
        return; // Ignore own packets
    }

    switch (packet->getPacketType()) {
        case HELLO:
            processHello(packet, src);
            break;
        case LSP:
            processLSP(packet, src);
            break;
        default:
            EV_WARN << "Unknown FSR packet type: " << packet->getPacketType() << endl;
            break;
    }
}

void Fsr::processHello(const Ptr<const FsrPacket> &packet, const Ipv4Address &sourceAddr)
{
    EV_INFO << "*** PROCESSING HELLO ***" << endl;
    EV_INFO << "From: " << sourceAddr << endl;
    EV_INFO << "Current neighbors count: " << neighbors.size() << endl;

    addNeighbor(sourceAddr);

    EV_INFO << "After adding neighbor, count: " << neighbors.size() << endl;
    EV_INFO << "Neighbors: ";
    for (const auto &neighbor : neighbors) {
        EV_INFO << neighbor << " ";
    }
    EV_INFO << endl;
    EV_INFO << "*** END PROCESSING HELLO ***" << endl;
}

void Fsr::processLSP(const Ptr<const FsrPacket> &packet, const Ipv4Address &sourceAddr)
{
    // Update statistics
    numLSPsReceived++;

    EV_INFO << "*** PROCESSING LSP ***" << endl;
    EV_INFO << "From: " << sourceAddr << endl;

    // Process the LSP - update topology table
    Ipv4Address originator = uint32ToIpv4(packet->getSourceAddress());
    uint32_t seq = packet->getSequenceNumber();

    // Check if this is a newer LSP
    auto it = topologyTable.find(originator);
    if (it != topologyTable.end()) {
        if (seq <= it->second.seq) {
            EV_INFO << "Ignoring old/duplicate LSP from " << originator << " (seq " << seq << ")" << endl;
            return;
        }
    }

    // Update topology table
    tt_entry_t &entry = topologyTable[originator];
    entry.seq = seq;
    entry.age = 0;
    entry.ls.clear();

    // Extract LSP entries
    for (unsigned int i = 0; i < packet->getLspEntriesArraySize(); i++) {
        const LspEntry &lspEntry = packet->getLspEntries(i);
        Ipv4Address nodeAddr = uint32ToIpv4(lspEntry.getNodeAddress());

        // Add the node itself to the topology
        entry.ls.insert(nodeAddr);

        // Add all neighbors of this node
        for (unsigned int j = 0; j < lspEntry.getNeighborsArraySize(); j++) {
            Ipv4Address neighborAddr = uint32ToIpv4(lspEntry.getNeighbors(j));
            entry.ls.insert(neighborAddr);
        }
    }

    EV_INFO << "Updated topology from " << originator << " (seq " << seq << ")" << endl;

    // Recalculate shortest paths
    calculateShortestPath();

    // Relay if hops remain
    if (packet->getHopCount() > 1) {
        // Build a fresh chunk and copy all fields
        Ptr<FsrPacket> relay(new FsrPacket());
        relay->setPacketType(packet->getPacketType());
        relay->setSourceAddress(packet->getSourceAddress());
        relay->setSequenceNumber(packet->getSequenceNumber());
        relay->setTimestamp(packet->getTimestamp());
        relay->setHopCount(packet->getHopCount() - 1);

        unsigned int n = packet->getLspEntriesArraySize();
        relay->setLspEntriesArraySize(n);
        for (unsigned int i = 0; i < n; ++i)
            relay->setLspEntries(i, packet->getLspEntries(i));

        // Send the relay packet using the helper function
        sendFsrPacketHelper(relay, Ipv4Address::ALLONES_ADDRESS);

        EV_INFO << "Relayed LSP (new hopCount=" << (int)relay->getHopCount() << ")" << endl;
    }
    EV_INFO << "*** END PROCESSING LSP ***" << endl;
}

void Fsr::sendHelloPacket()
{
    if (selfAddress.isUnspecified())
        return;

    // Build the FsrPacket chunk
    Ptr<FsrPacket> fsrchunk(new FsrPacket());
    fsrchunk->setPacketType(HELLO);
    fsrchunk->setSourceAddress(ipv4ToUint32(selfAddress)); // Convert to uint32_t
    fsrchunk->setSequenceNumber(++sequenceNumber);
    fsrchunk->setTimestamp(simTime().dbl()); // Convert to double
    fsrchunk->setHopCount(1);

    // Send the packet using the helper function
    sendFsrPacketHelper(fsrchunk, Ipv4Address::ALLONES_ADDRESS);

    // Stats
    numHellosSent++;
    EV_INFO << "Sent HELLO packet (seq=" << sequenceNumber << ")" << endl;
}

void Fsr::sendTopologyUpdate()
{
    if (selfAddress.isUnspecified() || neighbors.empty()) {
        EV_INFO << "Skipping LSP: no neighbors or invalid address" << endl;
        return;
    }

    EV_INFO << "*** SENDING LSP UPDATE ***" << endl;
    EV_INFO << "Neighbors count: " << neighbors.size() << endl;

    // Build FsrPacket chunk
    Ptr<FsrPacket> fsrchunk(new FsrPacket());
    fsrchunk->setPacketType(LSP);
    fsrchunk->setSourceAddress(ipv4ToUint32(selfAddress)); // Convert to uint32_t
    fsrchunk->setSequenceNumber(++sequenceNumber);
    fsrchunk->setTimestamp(simTime().dbl()); // Convert to double
    fsrchunk->setHopCount(10);

    // Create one LSP entry for this node
    fsrchunk->setLspEntriesArraySize(1);
    LspEntry entry;
    entry.setNodeAddress(ipv4ToUint32(selfAddress)); // Convert to uint32_t
    entry.setSequenceNumber(sequenceNumber);

    // Fill in neighbors array
    entry.setNeighborsArraySize(neighbors.size());
    int i = 0;
    for (const auto &neighbor : neighbors) {
        entry.setNeighbors(i++, ipv4ToUint32(neighbor)); // Convert to uint32_t
    }

    fsrchunk->setLspEntries(0, entry);

    // Send the packet using the helper function
    sendFsrPacketHelper(fsrchunk, Ipv4Address::ALLONES_ADDRESS);

    // Stats
    numLSPsSent++;
    EV_INFO << "Sent LSP (seq=" << sequenceNumber << ")" << endl;
    EV_INFO << "*** END SENDING LSP UPDATE ***" << endl;
}

void Fsr::sendFsrPacketHelper(const Ptr<FsrPacket> &fsrPacket, const Ipv4Address &destAddr)
{
    EV_INFO << "##########################################" << endl;
    EV_INFO << "### SENDING FSR PACKET ###" << endl;
    EV_INFO << "Node: " << getContainingNode(this)->getFullName() << endl;
    EV_INFO << "My IP: " << selfAddress << endl;
    EV_INFO << "Destination: " << destAddr << endl;
    EV_INFO << "Packet type: " << fsrPacket->getPacketType() << endl;

    Ipv4Address finalDestAddr = destAddr;
    if (destAddr == Ipv4Address::ALLONES_ADDRESS) {
        if (!primaryBroadcastAddress.isUnspecified() && primaryBroadcastAddress != Ipv4Address::ALLONES_ADDRESS) {
            finalDestAddr = primaryBroadcastAddress;
            EV_INFO << "Redirecting ALLONES_ADDRESS to subnet broadcast: " << finalDestAddr << endl;
        } else {
            EV_WARN << "Attempting to use ALLONES_ADDRESS as broadcast, but specific subnet broadcast was not determined or is ALLONES. Current primaryBroadcastAddress: " << primaryBroadcastAddress << endl;
        }
    }

    EV_INFO << "Node: " << getContainingNode(this)->getFullName() << endl;
    EV_INFO << "My IP: " << selfAddress << endl;
    EV_INFO << "Destination: " << finalDestAddr << " (Original dest: " << destAddr << ")" << endl; // Log both
    EV_INFO << "Packet type: " << fsrPacket->getPacketType() << endl;

    // Check UDP socket status
    logUdpActivity();

    // Serialize the FSR packet to bytes
    std::vector<uint8_t> data = serializeFsrPacket(fsrPacket);
    EV_INFO << "Serialized data size: " << data.size() << " bytes" << endl;

    // Print first few bytes for debugging
    EV_INFO << "First 10 bytes: ";
    for (size_t i = 0; i < std::min((size_t)10, data.size()); i++) {
        EV_INFO << (int)data[i] << " ";
    }
    EV_INFO << endl;

    // Create packet with proper name based on type
    const char *packetName = (fsrPacket->getPacketType() == HELLO) ? "FSR-HELLO" : "FSR-LSP";
    Packet *pkt = new Packet(packetName);

    // Create BytesChunk from the serialized data
    auto chunk = Ptr<BytesChunk>(new BytesChunk(data));
    pkt->insertAtBack(chunk);

    EV_INFO << "Created packet '" << packetName << "' with size: " << pkt->getByteLength() << " bytes" << endl;

    try {
        EV_INFO << "Attempting to send via UDP socket..." << endl;

        // Send via UDP socket
        socket.sendTo(pkt, destAddr, fsrPort);
        controlBytesSent += pkt->getByteLength();

        EV_INFO << "Packet sent successfully via socket!" << endl;
    }
    catch (const std::exception &e) {
        EV_ERROR << "Error sending FSR packet: " << e.what() << endl;
        delete pkt; // Clean up if send failed
    }
    EV_INFO << "### END SENDING ###" << endl;
    EV_INFO << "##########################################" << endl;
}

void Fsr::sendMessageToNeighbors(const Ptr<FsrPacket> &payload)
{
    sendFsrPacketHelper(payload, Ipv4Address::ALLONES_ADDRESS);
}

void Fsr::calculateShortestPath()
{
    if (!routingTable) {
        EV_ERROR << "Cannot calculate shortest path: routing table not available" << endl;
        return;
    }

    // Clear existing routes
    clearRoutes();

    // Dijkstra's algorithm implementation
    std::map<Ipv4Address, uint32_t> dist;
    std::map<Ipv4Address, Ipv4Address> prev;
    std::set<Ipv4Address> visited;

    // Initialize distances
    dist[selfAddress] = 0;
    for (const auto &entry : topologyTable) {
        if (entry.first != selfAddress) {
            dist[entry.first] = UINT32_MAX;
        }
    }

    // Add direct neighbors
    for (const auto &neighbor : neighbors) {
        dist[neighbor] = 1;
        prev[neighbor] = neighbor;
    }

    // Dijkstra's main loop
    while (visited.size() < topologyTable.size() + 1) {
        // Find minimum distance unvisited node
        Ipv4Address current;
        uint32_t minDist = UINT32_MAX;
        bool found = false;

        for (const auto &d : dist) {
            if (visited.find(d.first) == visited.end() && d.second < minDist) {
                current = d.first;
                minDist = d.second;
                found = true;
            }
        }

        if (!found || minDist == UINT32_MAX) {
            break;
        }

        visited.insert(current);

        // Update distances to neighbors of current node
        auto it = topologyTable.find(current);
        if (it != topologyTable.end()) {
            for (const auto &neighbor : it->second.ls) {
                if (visited.find(neighbor) == visited.end()) {
                    uint32_t newDist = dist[current] + 1;
                    if (newDist < dist[neighbor]) {
                        dist[neighbor] = newDist;
                        if (current == selfAddress) {
                            prev[neighbor] = neighbor;
                        } else {
                            prev[neighbor] = prev[current];
                        }
                    }
                }
            }
        }
    }

    updateRoutes(prev);
}

void Fsr::updateRoutes(std::map<Ipv4Address, Ipv4Address> &prev)
{
    for (const auto &entry : prev) {
        if (entry.first != selfAddress && entry.first != entry.second) {
            createRoute(entry.first, entry.second, 1);
        }
    }

    EV_INFO << "Updated routes for " << prev.size() << " destinations" << endl;
}

void Fsr::createRoute(const Ipv4Address &dst, const Ipv4Address &nexthop, uint32_t hopCount)
{
    if (!routingTable || !interfaceTable) {
        EV_ERROR << "Cannot create route: tables not available" << endl;
        return;
    }

    // Find appropriate interface
    NetworkInterface *ie = nullptr;
    for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
        NetworkInterface *iface = interfaceTable->getInterface(i);
        if (iface->isWireless() && !iface->isLoopback()) {
            ie = iface;
            break;
        }
    }

    if (!ie) {
        EV_ERROR << "No suitable interface found for route to " << dst << endl;
        return;
    }

    // Create route
    Ipv4Route *route = new Ipv4Route();
    route->setDestination(dst);
    route->setNetmask(Ipv4Address::ALLONES_ADDRESS);
    route->setNextHop(nexthop);
    route->setInterface(ie);
    route->setSourceType(IRoute::MANET);
    route->setMetric(hopCount);

    routingTable->addRoute(route);
}

void Fsr::clearRoutes()
{
    if (!routingTable) {
        return;
    }

    // Remove all MANET routes
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSourceType() == IRoute::MANET) {
            routingTable->deleteRoute(route);
        }
    }
}

void Fsr::addNeighbor(const Ipv4Address &neighbor)
{
    if (neighbors.find(neighbor) == neighbors.end()) {
        neighbors.insert(neighbor);

        // Cancel existing timeout timer
        auto it = neighborTimeouts.find(neighbor);
        if (it != neighborTimeouts.end()) {
            cancelAndDelete(it->second);
        }

        // Create new timeout timer
        cMessage *timeoutMsg = new cMessage("neighborTimeout");
        neighborTimeouts[neighbor] = timeoutMsg;
        scheduleAt(simTime() + 3 * helloBroadcastInterval, timeoutMsg);

        EV_INFO << "Added neighbor: " << neighbor << endl;
        EV_INFO << "Total neighbors now: " << neighbors.size() << endl;
    } else {
        // Reset timeout timer
        auto it = neighborTimeouts.find(neighbor);
        if (it != neighborTimeouts.end()) {
            cancelEvent(it->second);
            scheduleAt(simTime() + 3 * helloBroadcastInterval, it->second);
        }
        EV_INFO << "Refreshed neighbor timeout: " << neighbor << endl;
    }
}

void Fsr::removeNeighbor(const Ipv4Address &neighbor)
{
    neighbors.erase(neighbor);

    auto it = neighborTimeouts.find(neighbor);
    if (it != neighborTimeouts.end()) {
        cancelAndDelete(it->second);
        neighborTimeouts.erase(it);
    }

    EV_INFO << "Removed neighbor: " << neighbor << endl;
    EV_INFO << "Total neighbors now: " << neighbors.size() << endl;

    // Recalculate routes
    calculateShortestPath();
}

void Fsr::decrementAge()
{
    auto it = topologyTable.begin();
    while (it != topologyTable.end()) {
        it->second.age++;
        if (it->second.age > lifeTime) {
            EV_INFO << "Removing expired topology entry for " << it->first << endl;
            it = topologyTable.erase(it);
        } else {
            ++it;
        }
    }
}

void Fsr::initNode()
{
    // Initialize own entry in topology table
    tt_entry_t &ownEntry = topologyTable[selfAddress];
    ownEntry.seq = 0;
    ownEntry.age = 0;
    ownEntry.ls.clear();
}

void Fsr::printTopologyTable()
{
    EV_INFO << "=== Topology Table ===" << endl;
    for (const auto &entry : topologyTable) {
        EV_INFO << "Node: " << entry.first << " Seq: " << entry.second.seq
                << " Age: " << entry.second.age << " Neighbors: ";
        for (const auto &neighbor : entry.second.ls) {
            EV_INFO << neighbor << " ";
        }
        EV_INFO << endl;
    }
    EV_INFO << "======================" << endl;
}

void Fsr::finish()
{
    EV_INFO << "FSR Statistics:" << endl;
    EV_INFO << "LSPs sent: " << numLSPsSent << endl;
    EV_INFO << "LSPs received: " << numLSPsReceived << endl;
    EV_INFO << "HELLOs sent: " << numHellosSent << endl;
    EV_INFO << "Total packets received: " << numPacketsReceived << endl;
    EV_INFO << "Control bytes sent: " << controlBytesSent << endl;
    EV_INFO << "Final neighbor count: " << neighbors.size() << endl;

    printTopologyTable();
}

} // namespace fsr
} // namespace inet
