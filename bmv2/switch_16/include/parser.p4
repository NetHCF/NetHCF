/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

#define ETHERTYPE_IPV4 0x0800

parser ParserImpl(packet_in packet,
                    out headers hdr, 
                    inout metadata meta, 
                    inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        // need compute tcp length?
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                meta.tcpLength, 
                hdr.tcp.srcPort, 
                hdr.tcp.dstPort, 
                hdr.tcp.seqNo, 
                hdr.tcp.ackNo, 
                hdr.tcp.dataOffset, 
                hdr.tcp.res, 
                hdr.tcp.ecn, 
                hdr.tcp.urg, 
                hdr.tcp.ack, 
                hdr.tcp.psh, 
                hdr.tcp.rst, 
                hdr.tcp.syn, 
                hdr.tcp.fin, 
                hdr.tcp.window, 
                hdr.tcp.urgentPtr 
            }, 
            hdr.tcp.checksum, 
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}
