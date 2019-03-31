#!/usr/bin/env python
# coding=utf-8

import socket
import struct

CONTROLLER_IP = "192.168.56.101"
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
CACHE_SIZE = 13
# CACHE_SIZE = 100000

IP_SPACE_SIZE = 2**8
# IP_SPACE_SIZE = 2**25

LEARN_TO_FILTER_THR = 20
FILTER_TO_LEARN_THR = 15

DEVIDE_BITS = 8

DEFAULT_HC = 0

NOT_DELETE_HANDLE = -2

UPDATE_PERIOD = 5

BITMAP_ZERO_TO_TIMES = 0
BITMAP_ONE_TO_TIMES = 15

# HCF State Constant
HCF_LEARNING_STATE = 0
HCF_FILTERING_STATE = 1

# TCP Session Monitor State Constant
TCP_SESSION_INIT_OR_DONE_STATE = 0
TCP_SESSION_IN_PROGRESS_STATE = 1

# ImpactHeap(IH) Item: [impact_factor, ip_addr]
IMPACT_HEAP_IMPACT_FACTOR_FLAG = 0
IMPACT_HEAP_IP_ADDR_FLAG = 1
IMPACT_HEAP_PREFIX_LEN_FLAG = 2

# # IP2HC table Item: [prefix_len, Hop-Count, total_matched, last_matched]
# IP2HC table Item: [Hop-Count, total_matched, last_matched]
IP2HC_HIT_KEY = -1
# IP2HC_PREFIX_LEN_FLAG = 0
IP2HC_HOP_COUNT_FLAG = 0
IP2HC_TOTAL_MATCHED_FLAG = 1
IP2HC_LAST_MATCHED_FLAG = 2

# Cache Item: [ip_addr, prefix_len, entry_handle]
CACHE_IP_ADDR_FLAG = 0
CACHE_PREFIX_LEN_FLAG = 1
CACHE_ENTRY_HANDLE_FLAG = 2

# Update Scheme Structure: {cache_idx: (old_entry_handle, new_ip, new_hc)}
SCHEME_OLD_ENTRY_HANDLE_FLAG = 0
SCHEME_NEW_IP_ADDR_FLAG = 1
SCHEME_NEW_PREFIX_LEN_FLAG = 2
SCHEME_NEW_HOP_COUNT_FLAG = 3

BMV2_PATH = "/home/dracula/p4_environment/behavioral-model"
TARGET_THRIFT_IP = 'localhost'
TARGET_THRIFT_PORT = 22223
# TARGET_SWITCH = BMV2_PATH +  "/targets/simple_switch/sswitch_CLI"
# TARGET_CODE = "hop_count.json"
# TARGET_PORT = 22223

NETHCF_SWITCH_CONFIG = {
    # counter name in p4
    "miss_counter": "miss_counter",
    "mismatch_counter": "abnormal_counter",
    "ip2hc_counter": "hit_count",
    "ip2hc_counter_bitmap": "hit_bitmap",
    # hc value register array name in p4
    "ip2hc_register": "hop_count",
    # IP2HC Match-Action-Table name in p4
    "ip2hc_mat": "ip_to_hc_table",
    # IP2HC Match-Action-Table action name in p4
    "read_hc_function": "table_hit",
    # State register name in p4
    "hcf_state": "current_state",
    # Dirty Flag register name in p4
    "dirty_flag": "dirty_flag",
    # Dirty Bitmap register name in p4
    "dirty_bitmap": "dirty_bitmap"
}

DEBUG_OPTION = True

def impact_factor_function(total_matched, last_matched):
    impact_factor = ALPHA * total_matched + (1 - ALPHA) * last_matched
    return impact_factor

def number_to_be_replaced(miss_counter):
    return min(int(miss_counter * LAMBDA), THETA)

