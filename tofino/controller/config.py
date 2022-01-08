#!/usr/bin/env python
# coding=utf-8

import socket
import struct

CONTROLLER_IP = "10.0.0.254"
TYPE_IPV4 = 0x0800
TYPE_TCP = 0x06
FLAG_SYN = 0b000010
FLAG_ACK = 0b010000
# # TYPE_NETHCF_IP2HC is used for transfering counter arrays of switch
# TYPE_NETHCF_IP2HC = 0xAB
# # TYPE_NETHCF_MISX is used for transfering miss and mismatch counters
# TYPE_NETHCF_MISX = 0xCD
TYPE_NETHCF = 0xAB
ALPHA = 0.2
LAMBDA = 0.1
THETA = 20
CACHE_SIZE = 10
# CACHE_SIZE = 100000
INGRESS_PORT = 128
EGRESS_PORT = 136

IP_SPACE_SIZE = 2**8
# IP_SPACE_SIZE = 2**25

LEARN_TO_FILTER_THR = 100
FILTER_TO_LEARN_THR = 50

BMV2_PATH = "/home/dracula/p4_environment/behavioral-model"
TARGET_SWITCH = BMV2_PATH +  "/targets/simple_switch/sswitch_CLI"
TARGET_CODE = "hop_count.json"
TARGET_PORT = 22223

FILTERING_BATCH = 10

DEVIDE_BITS = 8

DEFAULT_HC = 0

NETHCF_SWITCH_CONFIG = {
    # project name in p4
    "project_name": "nethcf",
    # digest field list name
    "digest_fields": "digest_fields",
    # counter name in p4
    "miss_counter": "miss_counter",
    "mismatch_counter": "abnormal_counter",
    "ip2hc_counter": "hit_count",
    # hc value register array name in p4
    "ip2hc_register": "hop_count",
    # IP2HC Match-Action-Table name in p4
    "ip2hc_mat": "ip_to_hc_table",
    # IP2HC Match-Action-Table action name in p4
    "read_hc_function": "table_hit",
    # State register name in p4
    "hcf_state": "current_state"
}

DP_CONFIG = {
    "dp_interface": None,
    "sess_hdl": None,
    "dev_tgt": None,
    "dev": None,
    "hw_sync_flag": None,
    "set_default": {
        "hcf_check_table": {
            "action": "check_hcf",
            "parameter": [1, 1] # [Num, ...]
        },
        "packet_normal_table": {
            "action": "tag_normal",
            "parameter": [0] # [Num, ...]
        },
        "packet_abnormal_table": {
            "action": "tag_abnormal",
            "parameter": [0] # [Num, ...]
        },
        "hc_compute_table": {
            "action": "compute_hc",
            # "parameter": [1, 255] # [Num, ...]
            "parameter": [1, 127] # [Num, ...]
        },
        "hc_inspect_table": {
            "action": "inspect_hc",
            "parameter": [0] # [Num, ...]
        },
        "get_ip_table": {
            "action": "get_src_ip",
            "parameter": [0] # [Num, ...]
        },
        "ip_to_hc_table": {
            "action": "table_miss",
            "parameter": [0] # [Num, ...]
        },
        "ip_to_hc_table_2": {
            "action": "nop",
            "parameter": [0] # [Num, ...]
        },
        "hc_abnormal_table": {
            "action": "filtering_abnormal",
            "parameter": [0] # [Num, ...]
        },
        # "calculate_session_map_index_table": {
            # "action": "calculate_session_map_index",
            # "parameter": [0] # [Num, ...]
        # },
        "read_session_seq_table": {
            "action": "read_session_seq_action",
            "parameter": [0] # [Num, ...]
        },
        "session_table": {
            "action": "session_op",
            "parameter": [0] # [Num, ...]
        },
        "session_init_table_2": {
            "action": "init_session_2",
            "parameter": [0] # [Num, ...]
        },
        "session_complete_table_2": {
            "action": "complete_session_2",
            "parameter": [0] # [Num, ...]
        },
        "mark_syn_ack_table": {
            "action": "mark_syn_ack",
            "parameter": [0] # [Num, ...]
        },
        "mark_session_complete_condition_table": {
            "action": "session_complete_condition_cal",
            "parameter": [0] # [Num, ...]
        },
        "l2_forward_table": {
            "action": "_drop",
            "parameter": [0] # [Num, ...]
        },
        "miss_packet_clone_table": {
            "action": "packet_clone",
            "parameter": [0] # [Num, ...]
        },
        "miss_packet_clone_table_copy": {
            "action": "packet_clone",
            "parameter": [0] # [Num, ...]
        },
        # "modify_field_and_truncate_table": {
            # "action": "nop",
            # "parameter": [0] # [Num, ...]
        # },
        "packet_miss_table": {
            "action": "tag_abnormal",
            "parameter": [0] # [Num, ...]
        },
        "session_complete_update_table": {
            "action": "session_complete_update",
            "parameter": [0] # [Num, ...]
        },
    },
    "table_add": [
        {
            "table": "hcf_check_table",
            "action": "check_hcf",
            "match": [1, "exact", 2], # [num, type, ...]
            "parameter": [1, 0], # [Num, ...]
        },
        {
            "table": "hc_compute_table",
            "action": "compute_hc",
            "match": [1, "range", [0, 29]], # [num, type, ...]
            "parameter": [1, 30], # [Num, ...]
            "priority": 0
        },
        {
            "table": "hc_compute_table",
            "action": "compute_hc",
            "match": [1, "range", [30, 31]], # [num, type, ...]
            "parameter": [1, 32], # [Num, ...]
            "priority": 0
        },
        {
            "table": "hc_compute_table",
            "action": "compute_hc",
            "match": [1, "range", [32, 59]], # [num, type, ...]
            "parameter": [1, 60], # [Num, ...]
            "priority": 0
        },
        {
            "table": "hc_compute_table",
            "action": "compute_hc",
            "match": [1, "range", [60, 63]], # [num, type, ...]
            "parameter": [1, 64], # [Num, ...]
            "priority": 0
        },
        {
            "table": "hc_compute_table",
            "action": "compute_hc",
            "match": [1, "range", [64, 127]], # [num, type, ...]
            "parameter": [1, 127], # [Num, ...]
            "priority": 0
        },
        # {
        #     "table": "hc_compute_table",
        #     "action": "compute_hc",
        #     "match": [1, "range", [129, 254]], # [num, type, ...]
        #     "parameter": [1, 255], # [Num, ...]
        #     "priority": 0
        # },
        {
            "table": "get_ip_table",
            "action": "get_des_ip",
            "match": [2, "exact", 1, "exact", 1], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "ip_to_hc_table_2",
            "action": "nop",
            "match": [1, "exact", 0], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "ip_to_hc_table_2",
            "action": "table_hit_2",
            "match": [1, "exact", 1], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "hc_abnormal_table",
            "action": "learning_abnormal",
            "match": [1, "exact", 0], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "hc_abnormal_table",
            "action": "filtering_abnormal",
            "match": [1, "exact", 1], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "calculate_session_map_index_table",
            "action": "calculate_session_map_index",
            "match": [1, "exact", INGRESS_PORT], # ingress_port
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "calculate_session_map_index_table",
            "action": "reverse_calculate_session_map_index",
            "match": [1, "exact", EGRESS_PORT], # egress_port
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "l2_forward_table",
            "action": "forward_l2",
            "match": [2, "exact", 0, "exact", EGRESS_PORT], # ingress_port
            "parameter": [1, INGRESS_PORT], # egress_ports
        },
        {
            "table": "l2_forward_table",
            "action": "forward_l2",
            "match": [2, "exact", 0, "exact", INGRESS_PORT], # ingress_port
            "parameter": [1, EGRESS_PORT], # egress_ports
        },
        # {
            # "table": "modify_field_and_truncate_table",
            # "action": "only_truncate",
            # "match": [2, "exact", 0, "exact", 0], # [num, type, ...]
            # "parameter": [0], # [Num, ...]
        # },
        # {
            # "table": "modify_field_and_truncate_table",
            # "action": "modify_field_and_truncate",
            # "match": [2, "exact", 0, "exact", 1], # [num, type, ...]
            # "parameter": [0], # [Num, ...]
        # },
        # {
            # "table": "modify_field_and_truncate_table",
            # "action": "modify_field_and_truncate",
            # "match": [2, "exact", 1, "exact", 1], # [num, type, ...]
            # "parameter": [0], # [Num, ...]
        # },
        {
            "table": "packet_miss_table",
            "action": "tag_normal",
            "match": [1, "exact", 0], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
        {
            "table": "packet_miss_table",
            "action": "tag_abnormal",
            "match": [1, "exact", 1], # [num, type, ...]
            "parameter": [0], # [Num, ...]
        },
    ]
}

DEBUG_OPTION = True

def impact_factor_function(total_matched, last_matched):
    impact_factor = ALPHA * total_matched + (1 - ALPHA) * last_matched
    return impact_factor

def number_to_be_replaced(miss_counter):
    return min(int(miss_counter * LAMBDA), THETA)

