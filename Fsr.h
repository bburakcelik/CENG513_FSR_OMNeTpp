/*
 * Fsr.h
 * Fisheye State Routing Protocol for INET Framework
 */

#ifndef INET_ROUTING_FSR_FSR_H_
#define INET_ROUTING_FSR_FSR_H_

#include "inet/common/packet/Packet.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/networklayer/ipv4/Ipv4Route.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "inet/routing/fsr/FsrPacket_m.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/common/Ptr.h"
#include <cstdint>
#include <set>
#include <map>
#include <vector>

namespace inet {
namespace fsr {

/**
 * Fisheye State Routing (FSR) implementation for INET 4.x
 */
class INET_API Fsr : public RoutingProtocolBase, public UdpSocket::ICallback
{
  protected:
    // Topology table entry structure
    struct tt_entry_t {
        std::set<Ipv4Address> ls;  // Link state (neighbors)
        uint32_t seq;              // Sequence number
        uint32_t age;              // Age of entry
    };

    // UDP socket for communication
    UdpSocket socket;
    cModule *host = nullptr;

    // Direct module pointers (instead of ModuleRefByPar)
    IRoutingTable *routingTable = nullptr;
    IInterfaceTable *interfaceTable = nullptr;
    bool socketInitialized = false;

    // Node's IP address
    Ipv4Address selfAddress;
    Ipv4Address primaryBroadcastAddress;
    int outputInterfaceId = -1;

    // Timers
    cMessage *helloBroadcastTimer = nullptr;
    cMessage *lspUpdateTimer = nullptr;
    cMessage *decrementAgeTimer = nullptr;
    cMessage *lspLifeTimeTimer = nullptr;
    cMessage *testTimer = nullptr;

    // Configuration parameters
    double lspUpdateInterval;
    double helloBroadcastInterval;
    double maxWaitTimeForLspAnnouncement;
    double maxJitter;
    double lspLifeTimeInterval;
    int lifeTime;
    int fsrPort;

    // Statistics
    uint32_t controlBytesSent;
    uint32_t numLSPsSent;
    uint32_t numLSPsReceived;
    uint32_t numHellosSent;
    uint32_t numPacketsReceived;

    // FSR data structures
    std::map<Ipv4Address, cMessage *> neighborTimeouts;
    std::map<Ipv4Address, tt_entry_t> topologyTable;
    std::map<Ipv4Address, uint32_t> distanceTable;
    std::map<Ipv4Address, int> lifetimeTable;
    std::set<Ipv4Address> neighbors;
    uint32_t sequenceNumber;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    // UDP callback interface
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    // FSR protocol functions
    void processFsrPacket(const Ptr<const FsrPacket> &packet, const L3Address &sourceAddr);
    void processLSP(const Ptr<const FsrPacket> &packet, const Ipv4Address &sourceAddr);
    void processHello(const Ptr<const FsrPacket> &packet, const Ipv4Address &sourceAddr);
    void calculateShortestPath();
    void sendTopologyUpdate();
    void updateRoutes(std::map<Ipv4Address, Ipv4Address> &prev);
    void initNode();
    void decrementAge();

    // Helper functions
    void sendMessageToNeighbors(const Ptr<FsrPacket> &payload);
    void sendHelloPacket();
    void createRoute(const Ipv4Address &dst, const Ipv4Address &nexthop, uint32_t hopCount);
    void clearRoutes();
    void printTopologyTable();
    void removeNeighbor(const Ipv4Address &neighbor);
    void addNeighbor(const Ipv4Address &neighbor);
    void sendFsrPacketHelper(const Ptr<FsrPacket> &fsrPacket, const Ipv4Address &destAddr);
    Ptr<FsrPacket> deserializeFsrPacket(const Ptr<const BytesChunk> &bytesChunk);
    std::vector<uint8_t> serializeFsrPacket(const Ptr<FsrPacket> &fsrPacket);
    Ipv4Address getRouterId();

    // Debugging functions
    void logUdpActivity();
    void logInterfaceInfo();
    void logRoutingTableInfo();
    void testDirectCommunication();
    void sendTestUdpPacket();

    // Helper functions for address conversion
    uint32_t ipv4ToUint32(const Ipv4Address &addr) { return addr.getInt(); }
    Ipv4Address uint32ToIpv4(uint32_t addr) { return Ipv4Address(addr); }

  public:
    Fsr();
    virtual ~Fsr() override;
};

} // namespace fsr
} // namespace inet

#endif /* INET_ROUTING_FSR_FSR_H_ */
