#include "definitions.p4"

struct metadata {
    bit<1>  nethcf_enable_flag;
    bit<1>  nethcf_state;
    bit<HOP_COUNT_WIDTH>  packet_hop_count;
    bit<32> ip_for_match;
    bit<IP2HC_INDEX_WIDTH> ip2hc_index;
    bit<1>  ip2hc_hit_flag;
    bit<HOP_COUNT_WIDTH>  ip2hc_hop_count;
    bit<IP2HC_COUNTER_WIDTH>  ip2hc_counter_value;
    bit<1>  ip2hc_valid_flag;
    bit<1>  dirty_hc_hit_flag;
    bit<TEMPORARY_BITMAP_INDEX_WIDTH>  temporary_bitmap_index;
    bit<TEMPORARY_BITMAP_WIDTH> temporary_bitarray;
    bit<TEMPORARY_BITMAP_WIDTH> hop_count_bitarray;
    bit<1>  update_ip2hc_flag;
    bit<SESSION_INDEX_WIDTH>  session_index;
    bit<SESSION_STATE_WIDTH>  session_state;
    bit<32> session_seq;
    bit<SESSION_MONITOR_RESULT_WIDTH>  session_monitor_result;
    bit<32> ack_seq_diff;
    bit<PACKET_TAG_WIDTH>  packet_tag;
    bit<32> src_dst_ip;
    bit<16> src_dst_port;
    bit<48> src_dst_mac;

    bit<16> tcpLength;
}
