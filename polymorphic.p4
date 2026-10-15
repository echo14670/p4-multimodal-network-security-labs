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
const bit<16> POLY_MAGIC         = 0x504f;
const bit<8>  POLY_IP_PROTOCOL   = 253;
const bit<16> POLY_UDP_PORT      = 5000;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

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
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t sha;
    ip4Addr_t spa;
    macAddr_t tha;
    ip4Addr_t tpa;
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

header polyShim_t {
    bit<16> magic;
    bit<8>  direction;
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type;
}

header protected_data_t {
    bit<128> value;
}

header ipv6_t {
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

struct metadata {
    ip4Addr_t dst_ipv4;
}

struct headers {
    ethernet_t       ethernet;
    srcRoute_t[MAX_HOPS] srcRoutes;
    arp_t            arp;
    ipv4_t           ipv4;
    ipv6_t           ipv6;
    tcp_t            tcp;
    udp_t            udp;
    polyShim_t       polyShim;
    protected_data_t protected_data;
    ipv4_t           inner_ipv4;
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
            TYPE_IPV4:       parse_ipv4;
            TYPE_ARP:        parse_arp;
            TYPE_IPV6:       parse_ipv6;
            default:         accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1:        parse_ipv4;
            default:  parse_srcRouting;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            POLY_IP_PROTOCOL: parse_polyShim;
            6:                parse_tcp;
            17:               parse_udp;
            default:          accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            POLY_IP_PROTOCOL: parse_polyShim;
            6:                parse_tcp;
            17:               parse_udp;
            default:          accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            POLY_UDP_PORT: parse_protected_data;
            default:       accept;
        }
    }

    state parse_polyShim {
        packet.extract(hdr.polyShim);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            6:        parse_tcp;
            17:       parse_udp;
            default:  accept;
        }
    }

    state parse_protected_data {
        packet.extract(hdr.protected_data);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action start_polymorphic(bit<8> dir) {
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.ipv4.setInvalid();

        hdr.polyShim.setValid();
        hdr.polyShim.magic            = POLY_MAGIC;
        hdr.polyShim.direction        = dir;
        hdr.polyShim.sequence_number  = 1;
        hdr.polyShim.modality_id      = 0;
        hdr.polyShim.source_crc32     = 0;
        hdr.polyShim.inner_ether_type = 0x0800;

        standard_metadata.mcast_grp = 10;
    }

    table polymorphic_schedule {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr:              exact;
            hdr.udp.dstPort:               exact;
        }
        actions = {
            start_polymorphic;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

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

    action update_ttl() {
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

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table ipv6_lpm {
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
        hdr.ethernet.dstAddr = hdr.arp.sha;
        hdr.ethernet.srcAddr = macAddr;

        hdr.arp.oper = ARP_OPER_REPLY;
        hdr.arp.tha  = hdr.arp.sha;
        hdr.arp.tpa  = hdr.arp.spa;
        hdr.arp.sha  = macAddr;
        hdr.arp.spa  = meta.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_match {
        key = {
            hdr.arp.oper: exact;
            hdr.arp.tpa:  lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.udp.isValid() && hdr.udp.dstPort == POLY_UDP_PORT) {
            polymorphic_schedule.apply();
        }
        if (hdr.srcRoutes[0].isValid()) {
            if (hdr.srcRoutes[0].bos == 1) {
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()) {
                update_ttl();
            }
        }
        else if (hdr.ethernet.etherType == TYPE_IPV4) {
            ipv4_lpm.apply();
        }
        else if (hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if (hdr.ethernet.etherType == TYPE_IPV6) {
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
        if (hdr.polyShim.isValid()) {
            if (standard_metadata.egress_port == 2) {
                // 端口 2：外层 IPv4，protocol=253
                hdr.ethernet.etherType = 0x0800;
                hdr.ethernet.dstAddr   = 0x080000001100; // s11 的 MAC
                hdr.ipv4.setValid();
                hdr.ipv4.version   = 4;
                hdr.ipv4.ihl       = 5;
                hdr.ipv4.protocol  = POLY_IP_PROTOCOL;
                hdr.ipv4.srcAddr   = 0x0a000101; // 10.0.1.1
                hdr.ipv4.dstAddr   = 0x0a000202; // 10.0.2.2
                hdr.ipv4.totalLen  = 78;
                hdr.ipv4.ttl       = 64;
                hdr.polyShim.modality_id = 1;
            } else if (standard_metadata.egress_port == 3) {
                // 端口 3：外层 IPv6，nextHdr=253
                hdr.ethernet.etherType = 0x86dd;
                hdr.ethernet.dstAddr   = 0x080000001200; // s21 的 MAC
                hdr.ipv6.setValid();
                hdr.ipv6.version    = 6;
                hdr.ipv6.nextHdr    = POLY_IP_PROTOCOL;
                hdr.ipv6.hopLimit   = 64;
                hdr.ipv6.payLoadLen = 58;
                hdr.polyShim.modality_id = 2;
            } else if (standard_metadata.egress_port == 4) {
                // 端口 4：Source Routing，EtherType=0x1234
                hdr.ethernet.etherType = 0x1234;
                hdr.polyShim.modality_id = 3;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.polyShim);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.protected_data);
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
