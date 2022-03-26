/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
/*add*/
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;    //request message
const bit<16> ARP_OPER_REPLY     = 2;    //reply message

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

header arp_t {
    bit<16> htype;      //hardware type
    bit<16> ptype;      //protocol type
    bit<8>  hlen;       //hardwore size
    bit<8>  plen;       //protocol size
    bit<16> oper;       //oper==1 request  oper==2 reply
    macAddr_t  sha;     //sender mac address
    ip4Addr_t spa;      //sender ip address
    macAddr_t  tha;     //target mac address
    ip4Addr_t tpa;      //target ip address
}
struct metadata {
    ip4Addr_t dst_ipv4;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;     //transit to parse_ethernet
    }
    state parse_ethernet{             //user-defined state
      packet.extract(hdr.ethernet);   //extract packet header
      transition select(hdr.ethernet.etherType){
          TYPE_IPV4 : parse_arp_ipv4;
          ETHERTYPE_ARP : parse_arp;
          default:accept;
      }
    }
    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;       //target ip addr
        transition accept;
    }
    state parse_arp_ipv4 {
        packet.extract(hdr.ipv4);
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
  action drop() {
        mark_to_drop(standard_metadata);
        exit;
    }
    // exchange source ip and target ip , source mac and target mac
    action send_arp_reply(macAddr_t dstAddr, ip4Addr_t dst_ipv4) {

        hdr.ethernet.dstAddr = hdr.arp.sha;      //sourse_hardware_addr
        hdr.ethernet.srcAddr = dstAddr;         // dist max addr
        hdr.arp.oper         = ARP_OPER_REPLY;
        hdr.arp.tha     = hdr.arp.sha;           //target mac addr
        hdr.arp.tpa     = hdr.arp.spa;          //target ip addr
        hdr.arp.sha     = dstAddr;              //use the mac addr of gatway ,defined in table
        hdr.arp.spa     = dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    table arp_lpm{
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa             :lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
    }
     action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */

       standard_metadata.egress_spec = port;            //modify the port
       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;    //modify the MAC address
       hdr.ethernet.dstAddr = dstAddr;
       hdr.ipv4.ttl = hdr.ipv4.ttl - 1;                 //ttl minus one
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
    apply {
          if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
          }
          else if(hdr.arp.isValid()) {
             arp_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        /* ARP Case */
        packet.emit(hdr.arp);
        /* IPv4 case */
        packet.emit(hdr.ipv4);
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
