/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SRCROUTING    = 0x1234;

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

const bit<16> TYPE_IPV6          = 0x86DD;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

/*
 * CLASS-2 POLYMORPHIC SCHEDULING (module 2, milestones M1-M4)
 *
 *   M1 headers : polyShim_t, protectedData_t and a separate inner_ipv4   [done]
 *   M2 parser  : UDP/5000 experiment format plus the three encapsulated  [done]
 *                replica formats
 *   M3 ingress : traffic identification, sequence number, CRC32 and the  [done]
 *                multicast group that produces three replicas
 *   M4 egress  : IPv4 (protocol 253), IPv6 (next header 253) and Source  [done]
 *                Routing (EtherType 0x1234) outer headers
 *   M5/M6      : destination-gateway 2-out-of-3 adjudication, fault
 *                statistics and the transparent restore are the next
 *                lesson and are intentionally left unimplemented here.
 *
 * Wire format of a scheduled replica:
 *   Ethernet / outer modality header / PolyShim / inner IPv4 / UDP /
 *   protected_data
 */
const bit<16> POLY_MAGIC         = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL   = 253;
const bit<16> POLY_UDP_PORT      = 5000;
const bit<16> POLY_MCAST_GROUP   = 10;

const bit<8>  MODE_IPV4          = 1;
const bit<8>  MODE_IPV6          = 2;
const bit<8>  MODE_SR            = 3;

/* PolyShim is 112 bit (14 byte) on the wire. */
const bit<16> POLY_SHIM_BYTES    = 14;
/* Outer IPv4 header (20 byte) plus PolyShim in front of the inner packet. */
const bit<16> POLY_IPV4_OVERHEAD = 34;
const bit<8>  POLY_TTL           = 64;

/* Replica egress ports of the source gateway, one per modality. */
const bit<9>  PORT_MODE_IPV4     = 2;
const bit<9>  PORT_MODE_IPV6     = 3;
const bit<9>  PORT_MODE_SR       = 4;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

/* Outer IPv6 addresses taken from topo/topology.json. */
const ip6Addr_t H1_IPV6 = (ip6Addr_t)0xfe800000000000000000000000001234;
const ip6Addr_t H2_IPV6 = (ip6Addr_t)0xfe800000000000000000000000005678;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; //src mac address
    ip4Addr_t spa; //src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t{
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pkt_length;
    bit<16> checksum;
}

/* M1: experiment header carried between the outer modality header and the
 * original (inner) packet.  It is what makes the three replicas share one
 * sequence number, one direction and one reference CRC. */
header polyShim_t {
    bit<16> magic;
    bit<8>  direction;        // 0: h1 -> h2, 1: h2 -> h1
    bit<32> sequence_number;
    bit<8>  modality_id;      // 1: IPv4, 2: IPv6, 3: Source Routing
    bit<32> source_crc32;
    bit<16> inner_ether_type; // 0x0800
}

/* M1: fixed 16-byte experiment payload, short messages are zero padded. */
header protectedData_t {
    bit<128> value;
}

struct metadata {
    ip4Addr_t   dst_ipv4; // dst ip

    /* M3: scheduling metadata produced in ingress and read per replica in
     * egress.  Egress must not allocate sequence numbers because it runs once
     * per replica. */
    bit<1>      is_poly;
    bit<8>      direction;
    bit<32>     sequence_number;
    bit<32>     source_crc32;
}

struct headers {
    ethernet_t  ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t       arp;
    ipv4_t      ipv4;
    /* M1: the saved copy of the host packet's IPv4 header.  The outer IPv4
     * header of a replica reuses hdr.ipv4 (see MyEgress), so the two are never
     * valid at the same time. */
    ipv4_t      inner_ipv4;
    ipv6_t      ipv6;
    tcp_t       tcp;
    udp_t       udp;
    polyShim_t  polyShim;
    protectedData_t protectedData;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP : parse_arp;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_srcRouting_done;
            default: parse_srcRouting;
        }
    }

    /* M2: after the last hop of a source route either a PolyShim (scheduled
     * replica) or the plain IPv4 header of the original demo follows. */
    state parse_srcRouting_done {
        transition select(packet.lookahead<bit<16>>()) {
            POLY_MAGIC: parse_polyshim;
            default: parse_ipv4;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            POLY_IP_PROTOCOL: parse_polyshim;
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6{
	packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            POLY_IP_PROTOCOL: parse_polyshim;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        // M2: only the fixed UDP/5000 experiment format continues to the
        // protected data; ordinary UDP stays accepted without it.
        transition select(hdr.udp.dstPort) {
            POLY_UDP_PORT: parse_protected;
            default: accept;
        }
    }

    /* M2: scheduled replica, PolyShim followed by the saved inner packet. */
    state parse_polyshim {
        packet.extract(hdr.polyShim);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_protected {
        packet.extract(hdr.protectedData);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* M3: one shared sequence number per original experiment packet. */
    register<bit<32>>(1) seq_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
	
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action ipv6_forward(macAddr_t dstAddr,egressSpec_t port){
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }
    
    table ipv6_lpm{
    	key = {
	    hdr.ipv6.dstAddr: lpm;
	}
	actions = {
	    ipv6_forward;
	    drop;
	    NoAction;
	}		
	size = 1024;	
	default_action = drop();
    }

    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr; 	  // Ethernet source address = the action argument macAddr

        hdr.arp.oper         = ARP_OPER_REPLY;   // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha          = hdr.arp.sha;      // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa          = hdr.arp.spa;      // ARP target IP address = ARP source IP address
        hdr.arp.sha          = macAddr;          // ARP source MAC address = the action argument macAddr
        hdr.arp.spa          = meta.dst_ipv4;           // ARP source IP address = ARP target IP address

        standard_metadata.egress_spec = standard_metadata.ingress_port; // return to the port it comes from
    }

    table arp_match {
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa            : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    /* M3: identify the experiment packet on the host-facing port, save the
     * inner IPv4 header, allocate the shared sequence number and the reference
     * CRC32, and let the PRE duplicate the packet into group 10. */
    action start_polymorphic(bit<8> packet_direction) {
        bit<32> seq;
        seq_reg.read(seq, 0);
        seq = seq + 1;
        seq_reg.write(0, seq);

        hdr.inner_ipv4 = hdr.ipv4;
        hdr.ipv4.setInvalid();

        hdr.polyShim.setValid();
        hdr.polyShim.magic = POLY_MAGIC;
        hdr.polyShim.direction = packet_direction;
        hdr.polyShim.sequence_number = seq;
        hdr.polyShim.modality_id = 0;   // written per replica in MyEgress
        hdr.polyShim.inner_ether_type = TYPE_IPV4;

        // CRC32 over the stable fields: inner addresses, protocol, the two
        // transport ports and the fixed protected data.  TTL and the outer
        // addresses are excluded because they change along the paths.
        hash(meta.source_crc32, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.inner_ipv4.srcAddr, hdr.inner_ipv4.dstAddr,
               hdr.inner_ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort,
               hdr.protectedData.value },
             (bit<32>)0xFFFFFFFF);
        hdr.polyShim.source_crc32 = meta.source_crc32;

        meta.is_poly = 1;
        meta.direction = packet_direction;
        meta.sequence_number = seq;

        standard_metadata.mcast_grp = POLY_MCAST_GROUP;
    }

    table polymorphic_schedule {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            start_polymorphic;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /*
         * TODO M5: destination-gateway processing is inserted here in the next
         * lesson: it must either emit exactly one restored packet or drop, and
         * outer replica packets must never reach a host unchanged.
         */
        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }
        
        else if(hdr.ethernet.etherType == TYPE_IPV4) {
            polymorphic_schedule.apply();
            // Only ordinary IPv4 traffic keeps using the forwarding tables;
            // a scheduled packet is already owned by group 10.
            if (meta.is_poly == 0) {
                ipv4_lpm.apply();
            }
        }
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV6){
	    ipv6_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        /* M4: the PRE already picked the egress port, so the modality is
         * decided here from the read-only egress_port.  All three replicas
         * keep the sequence number and the CRC computed in ingress. */
        if (meta.is_poly == 1) {
            if (standard_metadata.egress_port == PORT_MODE_IPV4) {
                hdr.ipv4.setValid();
                hdr.ipv4.version = 4;
                hdr.ipv4.ihl = 5;
                hdr.ipv4.diffserv = 0;
                hdr.ipv4.totalLen = hdr.inner_ipv4.totalLen + POLY_IPV4_OVERHEAD;
                hdr.ipv4.identification = 0;
                hdr.ipv4.flags = 0;
                hdr.ipv4.fragOffset = 0;
                hdr.ipv4.ttl = POLY_TTL;
                hdr.ipv4.protocol = POLY_IP_PROTOCOL;
                hdr.ipv4.srcAddr = hdr.inner_ipv4.srcAddr;
                hdr.ipv4.dstAddr = hdr.inner_ipv4.dstAddr;
                hdr.ethernet.etherType = TYPE_IPV4;
                hdr.polyShim.modality_id = MODE_IPV4;
            }
            else if (standard_metadata.egress_port == PORT_MODE_IPV6) {
                hdr.ipv6.setValid();
                hdr.ipv6.version = 6;
                hdr.ipv6.trafficClass = 0;
                hdr.ipv6.flowLabel = 0;
                hdr.ipv6.payLoadLen = hdr.inner_ipv4.totalLen + POLY_SHIM_BYTES;
                hdr.ipv6.nextHdr = POLY_IP_PROTOCOL;
                hdr.ipv6.hopLimit = POLY_TTL;
                if (meta.direction == 0) {
                    hdr.ipv6.srcAddr = H1_IPV6;
                    hdr.ipv6.dstAddr = H2_IPV6;
                }
                else {
                    hdr.ipv6.srcAddr = H2_IPV6;
                    hdr.ipv6.dstAddr = H1_IPV6;
                }
                hdr.ethernet.etherType = TYPE_IPV6;
                hdr.polyShim.modality_id = MODE_IPV6;
            }
            else if (standard_metadata.egress_port == PORT_MODE_SR) {
                /* The source gateway itself does not consume a stack element
                 * (replication happens after ingress), so the replica carries
                 * the reference stacks h1->h2 "4 2 2 1" and h2->h1 "4 1 1 1"
                 * without their first hop: [2,2,1] and [1,1,1].
                 * push_front shifts the stack right, so the hops are pushed in
                 * reverse order and only the last one carries bos. */
                if (meta.direction == 0) {
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 1;
                    hdr.srcRoutes[0].port = 1;
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 0;
                    hdr.srcRoutes[0].port = 2;
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 0;
                    hdr.srcRoutes[0].port = 2;
                }
                else {
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 1;
                    hdr.srcRoutes[0].port = 1;
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 0;
                    hdr.srcRoutes[0].port = 1;
                    hdr.srcRoutes.push_front(1);
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos = 0;
                    hdr.srcRoutes[0].port = 1;
                }
                hdr.ethernet.etherType = TYPE_SRCROUTING;
                hdr.polyShim.modality_id = MODE_SR;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	/* This rule covers both the ordinary IPv4 header and the outer IPv4
	 * header rebuilt in egress, because both live in hdr.ipv4.  The inner
	 * IPv4 header is an untouched copy, so its checksum stays valid. */
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* M1/M4: emit in wire order.  Header validity decides which modality
         * is serialized, so ordinary traffic is unchanged. */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.polyShim);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.protectedData);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;