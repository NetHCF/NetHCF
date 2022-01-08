/*************************************************************************
    > File Name: hop_count.c
    > Author:
    > Mail:
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
************************************************************************/
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/intrinsic_metadata.p4"
#include "tofino/constants.p4"


#include "includes/headers.p4"
#include "includes/parser.p4"

#define HOP_COUNT_SIZE 8
#define HC_COMPUTE_TABLE_SIZE 8
#define TCP_SESSION_MAP_BITS 8
#define TCP_SESSION_MAP_SIZE 256 // 2^8
#define TCP_SESSION_STATE_SIZE 8
#define IP_TO_HC_INDEX_BITS 23
/* #define IP_TO_HC_TABLE_SIZE 65536 // 2^16 */
#define IP_TO_HC_TABLE_SIZE 10 // 2^16
#define SAMPLE_VALUE_BITS 3
#define PACKET_TAG_BITS 1
#define CONTROLLER_PORT 3 // Maybe this parameter can be stored in a register
#define PACKET_TRUNCATE_LENGTH 54
#define CLONE_SPEC_VALUE 250
#define CONTROLLER_IP_ADDRESS 167772414 //10.0.0.255
#define CONTROLLER_MAC_ADDRESS 0x000600000010

header_type meta_t {
    fields {
        packet_hop_count : HOP_COUNT_SIZE; // Hop Count of this packet
        ip2hc_hop_count : HOP_COUNT_SIZE; // Hop Count in ip2hc table
        tcp_session_map_index : TCP_SESSION_MAP_BITS;
        tcp_session_state : TCP_SESSION_STATE_SIZE; // 1:received SYN-ACK 0: exist or none
        tcp_seq_no: 32; // used for writing session_seq register
        tcp_session_seq : 32; // sequince number of SYN-ACK packet
        ip_to_hc_index: IP_TO_HC_INDEX_BITS;
        sample_value: SAMPLE_VALUE_BITS; // Used for sample packets
        hcf_state: 1; // 0: Learning 1: Filtering
        packet_tag: PACKET_TAG_BITS; // 0: Normal 1: Abnormal
        is_inspected: 1; // 0: Not Inspected 1: Inspected
        ip_for_match: 32; // IP address for searching the ip2hc table
        ip2hc_table_hit: 1; // 0: Not Hit 1 : Hit
        update_ip2hc: 1;
        session_complete_flag: 1;
        tcp_synack: 1;
        dstAddr : 32;
    }
}

metadata meta_t meta;

// The state of the switch, maintained by CPU(control.py)
// need `read` only
register current_state {
    width: 8;
    instance_count: 1;
}
blackbox stateful_alu read_current_state {
    reg: current_state;
    update_lo_1_value: register_lo; /*= do not update*/
    output_value: alu_lo;
    output_dst: meta.hcf_state;
}

// The number of abnormal packet per period
// it was a `counter` in bmv2 version
// write only
register abnormal_counter {
    width: 32;
    instance_count: 1;
}
blackbox stateful_alu update_abnormal_counter {
    reg: abnormal_counter;
    update_lo_1_value: register_lo + 1;
    initial_register_lo_value: 0;
}

// The number of missed packets
// it was a `counter` in bmv2 version
// write only
register miss_counter {
    width: 32;
    instance_count: 1;
}
blackbox stateful_alu update_miss_counter {
    reg: miss_counter;
    update_lo_1_value:  register_lo + 1;
    initial_register_lo_value: 0;
}

action check_hcf(is_inspected) {
    read_current_state.execute_stateful_alu(0);
    modify_field(meta.is_inspected, is_inspected);
}

// Used to get state(0:learning 1:filtering) of switch
// and judge whether the packet should be inspect by HCF
table hcf_check_table {
    reads {
        ig_intr_md.ingress_port : exact;
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

action inspect_hc() {
    read_hop_count.execute_stateful_alu(meta.ip_to_hc_index);
}

// Get the origin hop count of this source IP
table hc_inspect_table {
    actions { inspect_hc; }
}


// Save the hop count value of each source ip address
// need `read` and `write`
register hop_count {
    width : HOP_COUNT_SIZE;
    instance_count : IP_TO_HC_TABLE_SIZE;
}
blackbox stateful_alu read_hop_count {
    reg: hop_count;
    update_lo_1_value: register_lo;
    output_value: alu_lo;
    output_dst: meta.ip2hc_hop_count;
}
blackbox stateful_alu write_hop_count {
    reg: hop_count;
    update_lo_1_value: meta.packet_hop_count;
    output_value: alu_lo;
    output_dst: meta.packet_hop_count;
}

// Save the hit count value of each entry in ip2hc table
// it was a `counter` in bmv2 version
// write only
register hit_count {
    width: 32;
    instance_count : IP_TO_HC_TABLE_SIZE;
}
blackbox stateful_alu update_hit_count {
    reg: hit_count;
    update_lo_1_value: register_lo + 1;
    initial_register_lo_value: 0;
}

action get_src_ip() {
    modify_field(meta.ip_for_match, ipv4.srcAddr);
}

action get_des_ip() {
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
        get_des_ip;
    }
}

action table_miss() {
    update_miss_counter.execute_stateful_alu(0);
    modify_field(meta.ip2hc_table_hit, 0);
}

action table_hit(index) {
    modify_field(meta.ip_to_hc_index, index);
    modify_field(meta.ip2hc_table_hit, 1);
}
action table_hit_2() {
    update_hit_count.execute_stateful_alu(meta.ip_to_hc_index);
}

// The ip2hc table, if the current packet hits the ip2hc table, action
// table_hit is executed, otherwise action table_miss is executed
table ip_to_hc_table { /* update table_miss counter, and modify meta field */
    reads {
        meta.ip_for_match : exact;
    }
    actions {
        table_miss;
        table_hit;
    }
    max_size : IP_TO_HC_TABLE_SIZE;
}
table ip_to_hc_table_2 { /* update table_hit counter according to meta field */
    reads {
        meta.ip2hc_table_hit : exact; /* 1 for hit, 0 for nop */
    }
    actions {
        nop;
        table_hit_2;
    }
}

action learning_abnormal() {
    update_abnormal_counter.execute_stateful_alu(0);
    tag_normal();
}

action filtering_abnormal() {
    update_abnormal_counter.execute_stateful_alu(0);
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

action calculate_session_map_index() {
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
}

action reverse_calculate_session_map_index() {
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        reverse_tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
}

// Get packets' tcp session information. Notice: dual direction packets in one
// flow should belong to same tcp session and use same hash value
table calculate_session_map_index_table {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        calculate_session_map_index;
        reverse_calculate_session_map_index;
    }
}

// Read session_seq from register into meta
action read_session_seq_action() {
    read_session_seq.execute_stateful_alu(meta.tcp_session_map_index);
}
table read_session_seq_table {
    actions {
        read_session_seq_action;
    }
}

// Store sesscon state for concurrent tcp connections
// need `read` and `write`
register session_state {
    width : TCP_SESSION_STATE_SIZE;
    instance_count : TCP_SESSION_MAP_SIZE;
}
blackbox stateful_alu write_session_state {
    reg: session_state;

    update_hi_1_value: register_lo;

    condition_hi: meta.tcp_synack == 1;
    condition_lo: (register_lo & meta.session_complete_flag) == 1;
    // if syn+ack, init session
    update_lo_1_predicate: condition_hi;
    update_lo_1_value: 1;
    // if not syn+ack, and register_lo == 1, session_complete_flag == 1
    // session state := 0
    update_lo_2_predicate: condition_lo;
    update_lo_2_value: 0;


    output_value: alu_hi;
    output_dst: meta.tcp_session_state;
}

// Store sesscon sequince number(SYN-ACK's) for concurrent tcp connections
// need `read` and `write`
register session_seq {
    width: 32;
    instance_count : TCP_SESSION_MAP_SIZE;
}
blackbox stateful_alu read_session_seq {
    reg: session_seq;
    update_lo_1_value: register_lo;
    output_value: alu_lo;
    output_dst: meta.tcp_session_seq;
}
blackbox stateful_alu write_session_seq {
    reg: session_seq;
    update_lo_1_value: tcp.seqNo + 1;
    output_value: alu_lo;
    output_dst: meta.tcp_seq_no;
}
action session_op() {
    write_session_state.execute_stateful_alu(meta.tcp_session_map_index);
}
table session_table {
    actions {
        session_op;
    }
}

action init_session_2() {
    write_session_seq.execute_stateful_alu(meta.tcp_session_map_index);
}

// Someone is attempting to establsession_init_table
table session_init_table_2 {
    actions {
        init_session_2;
    }
}

action complete_session_2() {
    write_hop_count.execute_stateful_alu(meta.ip_to_hc_index);
    tag_normal();
}

// Establish the connection, and update IP2HC
table session_complete_table_2 {
    actions {
        complete_session_2;
    }
}
action mark_syn_ack() {
    modify_field(meta.tcp_synack, 1);
}
table mark_syn_ack_table {
    actions {
        mark_syn_ack;
    }
}

action session_complete_condition_cal() {
    modify_field(meta.session_complete_flag, 1);
}
table mark_session_complete_condition_table {
    actions {
        session_complete_condition_cal;
    }
}

action forward_l2(egress_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}

// Forward table, now it just support layer 2
table l2_forward_table {
    reads {
        meta.packet_tag : exact;
        ig_intr_md.ingress_port : exact;
    }
    actions {
        _drop;
        forward_l2;
    }
}

// Metadata used in clone function
/*field_list meta_data_for_clone {
    meta;
}*/

field_list digest_fields {
    ipv4.srcAddr;
    ipv4.ttl;
    ipv4.protocol;
    meta.dstAddr;
    tcp.seqNo;
    tcp.ackNo;
    tcp.urg;
    tcp.ack;
    tcp.psh;
    tcp.rst;
    tcp.syn;
    tcp.fin;
}

action packet_clone() {
    //modify_field(ig_intr_md_for_tm.ucast_egress_port, CONTROLLER_PORT);
    //clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
    modify_field(meta.dstAddr, ipv4.dstAddr);
    generate_digest(FLOW_LRN_DIGEST_RCVR, digest_fields);
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

/*action modify_field_and_truncate() {
    modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    // truncate(PACKET_TRUNCATE_LENGTH);
}*/

action nop() {
}

/*action only_truncate() {
    // truncate(PACKET_TRUNCATE_LENGTH);
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
}*/

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
    //modify_field(ig_intr_md_for_tm.ucast_egress_port, CONTROLLER_PORT);
    modify_field(meta.dstAddr, CONTROLLER_IP_ADDRESS);
    generate_digest(FLOW_LRN_DIGEST_RCVR, digest_fields);
}

// When a session is complete on the switch, the switch will send
// a packet to controller to update ip2hc table on the controller
table session_complete_update_table {
    actions {
        session_complete_update;
    }
}

control ingress {
    if (ig_intr_md.ingress_port == CONTROLLER_PORT) {
        // Packets from controller must be normal packets
        apply(packet_normal_table);
    }
    else {
        // Get basic infomation of switch
        apply(hcf_check_table);
        // calculate session_map_index
        apply(calculate_session_map_index_table);
        // Get ip address used to match ip_to_hc_table
        apply(get_ip_table);
        // Match ip_to_hc_table
        apply(ip_to_hc_table);
        apply(ip_to_hc_table_2);
        // Compute packet's hop count and refer to its origin hop count
        apply(hc_compute_table);


        // put all session_state related logics & tables here
        if (meta.ip2hc_table_hit == 1) {
            if(tcp.syn == 1 and tcp.ack == 1) {
                // session_init
                // if meta.ip2hc_table_hit == 1
                // write tcp.seqNo + 1 into session_seq table
                apply(mark_syn_ack_table);
                apply(session_init_table_2);
            }else {
                // session_complete
                apply(read_session_seq_table);
                if(tcp.ackNo == meta.tcp_session_seq and tcp.ack == 1){
                    apply(mark_session_complete_condition_table);
                }
            }
        }
        if (meta.ip2hc_table_hit == 1) {
            // Merged session_init table and session_complete table into one
            apply(session_table);
        }
        if (meta.ip2hc_table_hit == 1) {
            if(tcp.syn != 1 or tcp.ack != 1) {
                // session_complete
                // if meta.ip2hc_table_hit == 1
                // and tcp_session_state == 1
                // and tcp.ackNo == meta.tcp_session_seq
                // if tcp.ack == 1
                // write 0 into session_state register
                // write hop_count into hop_count register
                // tag_normal
                // elif tcp.ack != 1
                // tag_abnormal
                if(meta.session_complete_flag == 1){
                    // Legal connection, computes the hop count value and
                    // updates the ip2hc table on the switch and controller
                    if (meta.tcp_session_state == 1) {
                        apply(session_complete_table_2);
                        apply(session_complete_update_table);
                    }else {
                        apply(hc_inspect_table);
                    }
                }else {
                    apply(hc_inspect_table);
                }
            }
        }



        if (tcp.syn == 1 and tcp.ack == 1) {
            // For syn/ack packets
            if (meta.ip2hc_table_hit == 0) {
                apply(miss_packet_clone_table);
            }
            apply(packet_normal_table);
        }
        else {
            // Judge whether the current hits ip2hc table
            if (meta.ip2hc_table_hit == 1) {
                // Get session state
                if (meta.tcp_session_state == 1) {
                    // The connection is wainting to be established
                    if (tcp.ackNo != meta.tcp_session_seq or tcp.ack != 1) {
                        // Illegal connection attempt
                        apply(packet_abnormal_table);
                    }
                }
                else if (meta.tcp_session_state == 0) {
                    if (meta.is_inspected == 1) {
                        if (meta.packet_hop_count != meta.ip2hc_hop_count) {
                            // It's abnormal
                            apply(hc_abnormal_table);
                        }
                        else {
                            // It is normal
                            apply(packet_normal_table);
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
    /*if (ig_intr_md_for_tm.ucast_egress_port == CONTROLLER_PORT) {
        apply(modify_field_and_truncate_table);
    }*/
}
