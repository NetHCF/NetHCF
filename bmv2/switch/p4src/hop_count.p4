/*************************************************************************
    > File Name: hop_count.c
    > Author:
    > Mail:
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
************************************************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"

#define HOP_COUNT_SIZE 8
#define HIT_COUNT_SIZE 8
#define HC_COMPUTE_TABLE_SIZE 8
#define HC_COMPUTE_TWICE_TABLE_SIZE 3
#define TCP_SESSION_MAP_BITS 8
#define TCP_SESSION_MAP_SIZE 256 // 2^8
#define TCP_SESSION_STATE_SIZE 1
#define IP_TO_HC_INDEX_BITS 23
/* #define IP_TO_HC_TABLE_SIZE 65536 // 2^16 */
#define IP_TO_HC_TABLE_SIZE 13 // 2^16
#define SAMPLE_VALUE_BITS 3
#define PACKET_TAG_BITS 1
#define HIT_BITS 8
#define CONTROLLER_PORT 3 // Maybe this parameter can be stored in a register
#define PACKET_TRUNCATE_LENGTH 54
#define CLONE_SPEC_VALUE 250
#define CONTROLLER_IP_ADDRESS 0xC0A83865 //192.168.56.101
#define CONTROLLER_MAC_ADDRESS 0x000600000010

#define HIT_THRESHOLD 10

header_type meta_t {
    fields {
        packet_hop_count : HOP_COUNT_SIZE; // Hop Count of this packet
        ip2hc_hop_count : HOP_COUNT_SIZE; // Hop Count in ip2hc table
        hit_count_value : HIT_COUNT_SIZE; // Hit Count in hit_count table
        tcp_session_map_index : TCP_SESSION_MAP_BITS;
        tcp_session_state : TCP_SESSION_STATE_SIZE;
        // 1:received SYN-ACK 0: exist or none
        tcp_session_seq : 32; // sequence number of SYN-ACK packet
        ip_to_hc_index : IP_TO_HC_INDEX_BITS;
        sample_value : SAMPLE_VALUE_BITS; // Used for sample packets
        hcf_state : 1; // 0: Learning 1: Filtering
        packet_tag : PACKET_TAG_BITS; // 0: Normal 1: Abnormal
        is_inspected : 1; // 0: Not Inspected 1: Inspected
        ip_for_match : 32; // IP address for searching the ip2hc table
        ip2hc_table_hit : 1; // 0: Not Hit 1 : Hit
        update_ip2hc : 1;
        ip2hc_dirty_flag : 1;
        ip2hc_dirty_hc: 1;
    }
}

metadata meta_t meta;

// The state of the switch, maintained by CPU(control.py)
register current_state {
    width : 1;
    instance_count : 1;
}

// The number of abnormal packet per period
counter abnormal_counter {
    type : packets;
    instance_count : 1;
}

// The number of missed packets
counter miss_counter {
    type : packets;
    instance_count : 1;
}

action check_hcf(is_inspected) {
    register_read(meta.hcf_state, current_state, 0);
    modify_field(meta.is_inspected, is_inspected);
}

// Used to get state(0:learning 1:filtering) of switch
// and judge whether the packet should be inspect by HCF
table hcf_check_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions { check_hcf; }
}

action _drop() {
    drop();
}

action tag_normal() {
    modify_field(meta.packet_tag, 0);
}

// Tag the packet as normal
table packet_normal_table {
    actions { tag_normal; }
}

action tag_abnormal() {
    modify_field(meta.packet_tag, 1);
}

// Tag the packet as abnormal
table packet_abnormal_table {
    actions { tag_abnormal; }
}

action compute_hc(initial_ttl) {
    subtract(meta.packet_hop_count, initial_ttl, ipv4.ttl);
}

// According to final TTL, select initial TTL and compute hop count
table hc_compute_table {
    reads {
        ipv4.ttl : range;
    }
    actions {
        compute_hc;
    }
    max_size : HC_COMPUTE_TABLE_SIZE;
}

// Another for different pipeline
table hc_compute_table_copy {
    reads {
        ipv4.ttl : range;
    }
    actions {
        compute_hc;
    }
    max_size: HC_COMPUTE_TABLE_SIZE;
}

action inspect_hc() {
    register_read(meta.ip2hc_hop_count, hop_count, meta.ip_to_hc_index);
    register_read(meta.ip2hc_dirty_flag, dirty_flag, meta.ip_to_hc_index);
    register_read(meta.ip2hc_dirty_hc, dirty_bitmap, meta.packet_hop_count);
}

// Get the origin hop count of this source IP
table hc_inspect_table {
    actions { inspect_hc; }
}

// Save the hop count value of each source ip address
register hop_count {
    width : HOP_COUNT_SIZE;
    instance_count : IP_TO_HC_TABLE_SIZE;
}

// Save the hit count value of each entry in ip2hc table
register hit_count {
    width : HIT_COUNT_SIZE;
    instance_count : IP_TO_HC_TABLE_SIZE;
}

action update_hit_count() {
    register_read(meta.hit_count_value, hit_count, meta.ip_to_hc_index);
    add_to_field(meta.hit_count_value, 1);
    register_write(hit_count, meta.ip_to_hc_index, meta.hit_count_value);
}

table hit_count_update_table {
    actions { update_hit_count; }
}

register hit_bitmap {
    width : 1;
    instance_count : IP_TO_HC_TABLE_SIZE;
}

action set_hit_bitmap() {
    register_write(hit_bitmap, meta.ip_to_hc_index, 1);
}

table hit_bitmap_set_table {
    actions { set_hit_bitmap; }
}

// The flag bit to identify whether the iterm is dirty
register dirty_flag {
    width : 1;
    instance_count : IP_TO_HC_TABLE_SIZE;
}

register dirty_bitmap {
    width : 1;
    instance_count : 255;
}

action set_entry_to_dirty() {
    register_write(dirty_flag, meta.ip_to_hc_index, 1);
    register_read(meta.ip2hc_hop_count, hop_count, meta.ip_to_hc_index);
    register_write(dirty_bitmap, meta.ip2hc_hop_count, 1);
}

action get_src_ip() {
    modify_field(meta.ip_for_match, ipv4.srcAddr);
}

action get_dst_ip() {
    modify_field(meta.ip_for_match, ipv4.dstAddr);
}

// Get the IP address used to match ip_tp_hc_table
// For SYN/ACK packets, using src IP address
// For other packets, using dst IP address
table get_ip_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
    }
    actions {
        get_src_ip;
        get_dst_ip;
    }
}

action table_miss() {
    count(miss_counter, 0);
    modify_field(meta.ip2hc_table_hit, 0);
}

action table_hit(index) {
    modify_field(meta.ip_to_hc_index, index);
    modify_field(meta.ip2hc_table_hit, 1);
}

// The ip2hc table, if the current packet hits the ip2hc table, action
// table_hit is executed, otherwise action table_miss is executed
table ip_to_hc_table {
    reads {
        meta.ip_for_match : ternary;
    }
    actions {
        table_miss;
        table_hit;
    }
    max_size : IP_TO_HC_TABLE_SIZE;
}

action learning_abnormal() {
    count(abnormal_counter, 0);
    tag_normal();
}

action filtering_abnormal() {
    count(abnormal_counter, 0);
    tag_abnormal();
}

// If the packet is judged as abnormal because its suspected hop-count,
// handle it according to the switch state and whether the packet is sampled.
// For learning state: if the packet is sampled, just update abnormal_counter
// and tag it as normal(don't drop it); if the packet is not sampled, it won't
// go through this table because switch don't check its hop count.
// For filtering state, every abnormal packets should be dropped but update
// abnormal_counter specially for these sampled.
table hc_abnormal_table {
    reads {
        meta.hcf_state : exact;
    }
    actions {
        learning_abnormal;
        filtering_abnormal;
    }
}

field_list l3_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation tcp_session_map_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : TCP_SESSION_MAP_BITS;
}

field_list reverse_l3_hash_fields {
    ipv4.dstAddr;
    ipv4.srcAddr;
    ipv4.protocol;
    tcp.dstPort;
    tcp.srcPort;
}

field_list_calculation reverse_tcp_session_map_hash {
    input {
        reverse_l3_hash_fields;
    }
    algorithm : crc16;
    output_width : TCP_SESSION_MAP_BITS;
}

action lookup_session_map() {
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    register_read(
        meta.tcp_session_state, session_state,
        meta.tcp_session_map_index
    );
    register_read(
        meta.tcp_session_seq, session_seq,
        meta.tcp_session_map_index
    );
}

action lookup_reverse_session_map() {
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        reverse_tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    register_read(
        meta.tcp_session_state, session_state,
        meta.tcp_session_map_index
    );
    register_read(
        meta.tcp_session_seq, session_seq,
        meta.tcp_session_map_index
    );
}

// Get packets' tcp session information. Notice: dual direction packets in one
// flow should belong to same tcp session and use same hash value
table session_check_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        lookup_session_map;
        lookup_reverse_session_map;
    }
}

// Store session state for concurrent tcp connections
register session_state {
    width : TCP_SESSION_STATE_SIZE;
    instance_count : TCP_SESSION_MAP_SIZE;
}

// Store session sequence number(SYN-ACK's) for concurrent tcp connections
register session_seq {
    width : 32;
    instance_count : TCP_SESSION_MAP_SIZE;
}

action init_session() {
    register_write(session_state, meta.tcp_session_map_index, 1);
    register_write(session_seq, meta.tcp_session_map_index, tcp.seqNo);
}

// Someone is attempting to establish a connection from server
table session_init_table {
    actions {
        init_session;
    }
}

action complete_session() {
    // Set IP2HC table entry to dirty
    set_entry_to_dirty();
    // Update
    register_write(session_state, meta.tcp_session_map_index, 0);
    register_write(hop_count, meta.ip_to_hc_index, meta.packet_hop_count);
    tag_normal();
}

// Establish the connection, and update IP2HC
table session_complete_table {
    reads {
        tcp.ack : exact;
    }
    actions {
        tag_abnormal;
        complete_session;
    }
}

action forward_l2(egress_port) {
    modify_field(standard_metadata.egress_spec, egress_port);
}

// Forward table, now it just support layer 2
table l2_forward_table {
    reads {
        meta.packet_tag : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        _drop;
        forward_l2;
    }
}

// Metadata used in clone function
field_list meta_data_for_clone {
    standard_metadata;
    meta;
}

action packet_clone() {
    //modify_field(standard_metadata.egress_spec, CONTROLLER_PORT);
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

// When a packet is missed, clone it and send it to controller
table miss_packet_clone_table {
    actions {
        packet_clone;
    }
}

// For a different pipeline
table miss_packet_clone_table_copy {
    actions {
        packet_clone;
    }
}

action modify_field_and_truncate() {
    modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    truncate(PACKET_TRUNCATE_LENGTH);
}

action nop() {
}

action only_truncate() {
    truncate(PACKET_TRUNCATE_LENGTH);
}

// Only the packets' header are send to controller
table modify_field_and_truncate_table {
    reads {
        meta.hcf_state : exact;
        meta.update_ip2hc : exact;
    }
    actions {
        modify_field_and_truncate;
        only_truncate;
        nop;
    }
}

// The packets that missed ip_to_hc_table, deciding whether
// to forward them by current switch state
table packet_miss_table {
    reads {
        meta.hcf_state : exact;
    }
    actions {
        tag_normal;
        tag_abnormal;
    }
}

action session_complete_update() {
    //modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    //modify_field(standard_metadata.egress_spec, CONTROLLER_PORT);
    modify_field(meta.update_ip2hc, 1);
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

// When a session is complete on the switch, the switch will send
// a packet to controller to update ip2hc table on the controller
table session_complete_update_table {
    actions {
        session_complete_update;
    }
}

control ingress {
    if (standard_metadata.ingress_port == CONTROLLER_PORT) {
        // Packets from controller must be normal packets
        apply(packet_normal_table);
    }
    else {
        // Get basic information of switch
        apply(hcf_check_table);
        // Get session state
        apply(session_check_table);
        // Get ip address used to match ip_to_hc_table
        apply(get_ip_table);
        // Match ip_to_hc_table
        apply(ip_to_hc_table);
        if (tcp.syn == 1 and tcp.ack == 1) {
            // For syn/ack packets
            if (meta.ip2hc_table_hit == 0)
                apply(miss_packet_clone_table);
            else
                apply(session_init_table);
            apply(packet_normal_table);
        }
        else {
            // Judge whether the current hits ip2hc table
            if (meta.ip2hc_table_hit == 1) {
                // Get session state
                if (meta.tcp_session_state == 1) {
                    // The connection is waiting to be established
                    if (tcp.ackNo == meta.tcp_session_seq + 1) {
                        // Legal connection, computes the hop count value and
                        // updates the ip2hc table on the switch and controller
                        apply(hc_compute_table_copy);
                        apply(session_complete_table);
                        apply(session_complete_update_table);
                    }
                    else {
                        // Illegal connection attempt
                        apply(packet_abnormal_table);
                    }
                }
                else if (meta.tcp_session_state == 0) {
                    if (meta.is_inspected == 1) {
                        // Compute packet's hop count
                        // and refer to its origin hop count
                        apply(hc_compute_table);
                        apply(hc_inspect_table);
                        if ((meta.packet_hop_count == meta.ip2hc_hop_count) or
                            (meta.ip2hc_dirty_flag == 1 and
                             meta.ip2hc_dirty_hc == 1)) {
                            // It is normal
                            // Only update hit count when the packet is legal
                            apply(hit_count_update_table);
                            if (meta.hit_count_value > HIT_THRESHOLD) {
                                apply(hit_bitmap_set_table);
                            }
                            apply(packet_normal_table);
                        }
                        else {
                            // It's abnormal
                            apply(hc_abnormal_table);
                        }
                    }
                    else {
                        // We assume that packets from one side of
                        // the switch are normal packets
                        apply(packet_normal_table);
                    }
                }
            }
            else if (meta.ip2hc_table_hit == 0)
            {
                // Missed packets
                apply(miss_packet_clone_table_copy);
                apply(packet_miss_table);
            }
        }
    }
    // Drop abnormal packets and forward normal packets in layer two
    apply(l2_forward_table);
}

control egress {
    // Judging whether to send a header or a whole packet
    if (standard_metadata.egress_port == CONTROLLER_PORT) {
        apply(modify_field_and_truncate_table);
    }
}
