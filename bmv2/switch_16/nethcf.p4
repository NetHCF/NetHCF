#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/metadata.p4"
#include "include/parser.p4"

// The state of the switch, maintained by CPU(control.py)
register<bit<1>>(32w1) nethcf_state;
// Save the hit count value of each entry in IP2HC table
register<bit<8>>(32w13) ip2hc_counter;
// The flag bit array of IP2HC to identify whether the IP2HC iterm is dirty
register<bit<1>>(32w13) ip2hc_valid_flag;
// Temporary bitmap for storing  updated Hop Count value
register<bit<32>>(32w16) temporary_bitmap;
// Bitarray used to identify whether the IP2HC entry is hot
register<bit<1>>(32w13) report_bitarray;
// Store session state for concurrent tcp connections
register<bit<2>>(32w256) session_state;
// Store session sequence number(SYN-ACK's) for concurrent tcp connections
register<bit<32>>(32w256) session_seq;
// The number of abnormal packet per period
counter(32w1, CounterType.packets) mismatch_counter;
// The number of missed packets
counter(32w1, CounterType.packets) miss_counter;

control ingress(inout headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t standard_metadata) {
    
    // Used to get state(0:learning 1:filtering) of switch
    // and judge whether the packet should be inspect by nethcf
    action enable_nethcf(bit<1> nethcf_enable_flag) {
        meta.nethcf_enable_flag = nethcf_enable_flag;
    }

    table nethcf_enable_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            enable_nethcf;
        }
        size = NETHCF_ENABLE_TABLE_SIZE;
    }

    // Get the IP address used to match ip2hc_table
    // For SYN/ACK packets, using dst IP address
    // For other packets, using src IP address
    action prepare_src_ip() {
        nethcf_state.read(meta.nethcf_state, (bit<32>)0);
        meta.ip_for_match = hdr.ipv4.srcAddr;
    }

    action prepare_dst_ip() {
        nethcf_state.read(meta.nethcf_state, (bit<32>)0);
        meta.ip_for_match = hdr.ipv4.dstAddr;
    }

    table nethcf_prepare_table {
        key = {
            hdr.tcp.syn : exact;
            hdr.tcp.ack : exact;
        }
        actions = {
            prepare_src_ip;
            prepare_dst_ip;
        }
        size = NETHCF_PREPARE_TABLE_SIZE;
    }

    // The IP2HC table, if the current packet hits the IP2HC table, action
    // table_hit is executed, otherwise action table_miss is executed
    action table_miss() {
        miss_counter.count(32w0);
        meta.ip2hc_hit_flag = 0;
    }

    action table_hit(bit<IP2HC_INDEX_WIDTH> index, bit<HOP_COUNT_WIDTH> hop_count) {
        meta.ip2hc_index = index;
        meta.ip2hc_hop_count = hop_count;
        meta.ip2hc_hit_flag = 1;
    }

    table ip2hc_table {
        key = {
            meta.ip_for_match : ternary;
        }
        actions = {
            table_miss;
            table_hit;
        }
        size = IP2HC_TABLE_SIZE;
    }

    // According to final TTL, select initial TTL and compute Hop Count
    action inspect_hc(bit<HOP_COUNT_WIDTH> initial_ttl) {
        meta.packet_hop_count = initial_ttl - hdr.ipv4.ttl;
    }

    
    table hc_inspect_table {
        key = {
            hdr.ipv4.ttl : range;
        }
        actions = {
            inspect_hc;
        }
        size = HC_INSPECT_TABLE_SIZE;
    }

    // Update ip2hc_counter
    action update_ip2hc_counter() {
        ip2hc_counter.read(meta.ip2hc_counter_value, (bit<32>)meta.ip2hc_index);
        meta.ip2hc_counter_value = meta.ip2hc_counter_value + 8w1;
        ip2hc_counter.write((bit<32>)meta.ip2hc_index, (bit<8>)meta.ip2hc_counter_value);
    }
    
    // Get packets' tcp session information. Notice: dual direction packets in one
    // flow should belong to same tcp session and use same hash value
    action prepare_for_session_monitor() {
        meta.src_dst_ip = hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        meta.src_dst_port = hdr.tcp.srcPort ^ hdr.tcp.dstPort;
        hash(meta.session_index, HashAlgorithm.crc16, (bit<8>)0, { meta.src_dst_ip, hdr.ipv4.protocol }, (bit<16>)256);
        session_state.read(meta.session_state, (bit<32>)meta.session_index);
        session_seq.read(meta.session_seq, (bit<32>)meta.session_index);
        meta.ack_seq_diff = hdr.tcp.ackNo - meta.session_seq;
    }

    // Mointor tcp session according to expected state transition
    action monitor_session(bit<3> session_monitor_result) {
        meta.session_monitor_result = session_monitor_result;
    }

    table session_monitor_table {
        actions = {
            monitor_session;
        }
        key = {
            hdr.tcp.syn : exact;
            hdr.tcp.ack : exact;
            meta.ack_seq_diff : ternary;
            meta.session_state : ternary;
        }
        size = 10;
    }

    // Receive the first SYN packet, employ SYN Cookie to defend
    action init_syn_cookie() {
        // FIRST_SYN => SYNACK_WITHOUT_PROXY
        hdr.tcp.syn = 1w1;
        hdr.tcp.ack = 1w1;
        hdr.tcp.ackNo = hdr.tcp.seqNo + 32w1;
        hdr.tcp.seqNo = (bit<32>)meta.session_index;
        meta.src_dst_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = meta.src_dst_mac;
        meta.src_dst_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = meta.src_dst_ip;
        meta.src_dst_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = meta.src_dst_port;
        session_seq.write((bit<32>)meta.session_index, (bit<32>)hdr.tcp.seqNo);
        session_state.write((bit<32>)meta.session_index, (bit<2>)2);
        meta.packet_tag = 2w2;
    }

    // Someone is attempting to establish a connection from server
    action init_session() {
        session_state.write((bit<32>)meta.session_index, (bit<2>)1);
        session_seq.write((bit<32>)meta.session_index, (bit<32>)hdr.tcp.seqNo);
    }

    // Establish the connection, and update IP2HC
    action complete_session() {
        // Update tcp session state
        session_state.write((bit<32>)meta.session_index, (bit<2>)0);
    }

    // Pass SYN Cookie inspection, and restart session monitor like learning state
    action restart_session_monitor() {
        // Reset session state
        session_state.write((bit<32>)meta.session_index, (bit<2>)0);
    }

    action tag_packet_abnormal() {
        meta.packet_tag = 2w1;
    }

    action tag_packet_normal() {
        meta.packet_tag = 2w0;
    }

    action read_from_temporary_bitmap() {
        // Compute the index value (row number) of temporary bitmap
        hash(meta.temporary_bitmap_index, HashAlgorithm.crc16, (bit<4>)0, { meta.ip_for_match }, (bit<8>)16);
        // Read the row (bitarray) from the temporary bitmap
        temporary_bitmap.read(meta.temporary_bitarray, (bit<32>)meta.temporary_bitmap_index);
        meta.temporary_bitarray = meta.temporary_bitarray >> meta.packet_hop_count;
        meta.dirty_hc_hit_flag = (bit<1>)meta.temporary_bitarray & 1w1;
    }

    // Except for HC computing, check whether the IP2HC item is dirty
    action reinspect_hc() {
        ip2hc_valid_flag.read(meta.ip2hc_valid_flag, (bit<32>)meta.ip2hc_index);
        read_from_temporary_bitmap();
    }

    // If the packet is judged as abnormal because its suspected hop-count,
    // handle it according to the nethcf state.
    // For learning state, just update mismatch_counter
    // For filtering state, every abnormal packets should be dropped and
    // mismatch_counter should be updated as well
    action process_mismatch_at_filtering() {
        mismatch_counter.count((bit<32>)32w0);
        tag_packet_abnormal();
    }
    
    action process_mismatch_at_learning() {
        mismatch_counter.count((bit<32>)32w0);
    }

    // Set report_bitarray
    action set_report_bitarray() {
        report_bitarray.write((bit<32>)meta.ip2hc_index, (bit<1>)1);
    }

    // When a packet is missed, direct it to controller at filtering state
    action process_miss_at_filtering() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata, meta });
        tag_packet_abnormal();
    }

    // When a packet is missed, clone it to controller and pass it at learning state
    action process_miss_at_learning() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata, meta });
    }

    // Forward back the packet
    action forward_back() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action write_to_temporary_bitmap() {
        // Compute the index value (row number) of temporary bitmap
        hash(meta.temporary_bitmap_index, HashAlgorithm.crc16, (bit<4>)0, { meta.ip_for_match }, (bit<8>)16);
        // Read the row (bitarray) from the temporary bitmap
        temporary_bitmap.read(meta.temporary_bitarray, (bit<32>)meta.temporary_bitmap_index);
        // Compute the corresponding bitarray according to new Hop Count of packets
        meta.hop_count_bitarray = 32w1 << meta.packet_hop_count;
        // Compute the new row
        meta.temporary_bitarray = meta.temporary_bitarray | meta.hop_count_bitarray;
        // Write the new row back to temporary bitmap
        temporary_bitmap.write((bit<32>)meta.temporary_bitmap_index, (bit<32>)meta.temporary_bitarray);
    }

    action set_entry_to_dirty() {
        ip2hc_valid_flag.write((bit<32>)meta.ip2hc_index, (bit<1>)1);
        // Store the new Hop Count into the dirty bitmap
        write_to_temporary_bitmap();
    }
    
    // When a session is complete on the switch, the switch will send
    // a packet to controller to update IP2HC table on the controller
    action update_controller() {
        meta.update_ip2hc_flag = 1w1;
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata, meta });
    }

    // Update Hop Count at switch and controller
    // action update_hc() {
    //     set_entry_to_dirty();
    //     update_controller();
    // }

    // Forward table, now it just support layer 2
    action forward_l2(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    table l2_forward_table {
        actions = {
            _drop;
            forward_l2;
        }
        key = {
            standard_metadata.ingress_port: exact;
        }
        size = 10;
    }

    // This connection pass SYN Cookie check, let the client reconnect
    action complete_syn_cookie() {
        // Return RST packet
        hdr.tcp.ack = 1w0;
        hdr.tcp.psh = 1w0;
        hdr.tcp.rst = 1w1;
        hdr.tcp.seqNo = meta.session_seq + 32w1;
        hdr.tcp.ackNo = 32w0;
        // Exchange src and dst mac address
        meta.src_dst_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = meta.src_dst_mac;
        // Exchange src and dst ip address
        meta.src_dst_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = meta.src_dst_ip;
        // Exchange src and dst port
        meta.src_dst_port = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = meta.src_dst_port;
        // Update session state
        session_state.write((bit<32>)meta.session_index, (bit<2>)3);
        // Tag the packet to forward it back
        meta.packet_tag = 2w2;
    }

    apply {
        // Tag all packets as normal first
        meta.packet_tag = NORMAL_FLAG;
        // Check whether NetHCF is enabled
        nethcf_enable_table.apply();
        if(meta.nethcf_enable_flag == 1) {
            // Get ip address used to match the IP2HC mapping table
            nethcf_prepare_table.apply();
            // Match the IP2HC mapping table
            ip2hc_table.apply();
            if(meta.ip2hc_hit_flag == 1) {
                hc_inspect_table.apply();
                if(meta.ip2hc_hop_count == meta.packet_hop_count) {
                    // It is normal
                    // Only update hit count when the Hop Count is correct
                    update_ip2hc_counter();
                }
                else {
                    // Operate tcp session monitoring
                    prepare_for_session_monitor();
                    session_monitor_table.apply();
                    if(meta.session_monitor_result == FIRST_SYN) {
                        if(meta.nethcf_state == FILTERING_STATE) {
                            // SYN Cookie is enabled to defend SYN DDoS at filtering
                           init_syn_cookie(); // send SYNACK
                        }
                    }
                    else if (meta.session_monitor_result == SYNACK_WITHOUT_PROXY) {
                        // Received SYN/ACK packet, need to init TCP session
                        init_session();
                    }
                    else if (meta.session_monitor_result == ACK_WITHOUT_PROXY) {
                        // Legal connection established, compute the Hop Count value
                        // and updates the IP2HC table on the switch and controller
                        complete_session();
                        // Set IP2HC table entry to dirty
                        set_entry_to_dirty();
                        update_controller();
                    }
                    else if (meta.session_monitor_result == ACK_WITH_PROXY) {
                        complete_syn_cookie(); // send RST
                    }
                    else if (meta.session_monitor_result == SYN_AFTER_PROXY) {
                        // The second syn which after SYN Cookie inspection
                        // Let this packet pass, and restart session monitor
                        restart_session_monitor();
                    }
                    else if (meta.session_monitor_result == MONITOR_ABNORMAL) {
                        // Illegal connection attempt
                        tag_packet_abnormal();
                    }
                    else {
                        // Packets pass TCP session monitoring, compute packet's hop
                        // count and refer to its original Hop Count
                        reinspect_hc();
                        if((meta.ip2hc_valid_flag & meta.dirty_hc_hit_flag) == 1) {
                            // Only update hit count when the Hop Count is correct
                            update_ip2hc_counter();
                        }
                        else {
                            // Suspicious packets with mismatched Hop Count value
                            if(meta.nethcf_state == LEARNING_STATE) {
                                process_mismatch_at_learning();
                            }
                            else {
                                process_mismatch_at_filtering();
                            }
                        }
                    }
                }
                // Hot IP2HC entry process
                if(meta.ip2hc_counter_value > IP2HC_HOT_THRESHOLD) {
                    set_report_bitarray();
                }
            }
            else {
                // IP is not cached in IP2HC
                if (meta.nethcf_state == LEARNING_STATE) {
                    process_miss_at_learning();
                }
                else {
                    process_miss_at_filtering();
                }
            }
        }
        
        // Drop abnormal packets and forward normal packets in layer two
        if (meta.packet_tag == NORMAL_FLAG) {
            // Normal packets
            l2_forward_table.apply();
        }
        else if (meta.packet_tag == ABNORMAL_FLAG) {
            // Abnormal packets
            mark_to_drop(standard_metadata);
        }
        else {
            forward_back();
        }
    }
}

control egress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    // For the final ack packet of handshaking, change the dst ip to tell controller
    // this is a Hop Count update message
    action process_hc_update() {
        hdr.ipv4.dstAddr = CONTROLLER_IP_ADDRESS;
        truncate(PACKET_TRUNCATE_LENGTH);
    }
    
    // At learning state, for the cloned missed packet which should be sent to
    // controller, truncate it to only send digest to the controller
    action process_cloned_miss_at_learning() {
        truncate(PACKET_TRUNCATE_LENGTH);
    }
    
    // At filtering state, for the cloned missed packet which should be sent to
    // controller, direct the whole packet to the controller
    action process_cloned_miss_at_filtering() {
    }

    apply {
        // Judging whether to send a header or a whole packet
        if (standard_metadata.egress_port == CONTROLLER_PORT) {
            if (meta.update_ip2hc_flag == 1) {
                process_hc_update();
            }
            else if (meta.nethcf_state == LEARNING_STATE) {
                process_cloned_miss_at_learning();
            }
            else if (meta.nethcf_state == FILTERING_STATE) {
                process_cloned_miss_at_filtering();
            }
        }
    }
}

V1Switch(
    ParserImpl(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    DeparserImpl()
) main;
