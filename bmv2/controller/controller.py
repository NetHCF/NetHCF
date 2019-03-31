#!/usr/bin/env python
# coding=utf-8

from scapy.all import *
from data_structure import IP2HC, TCP_Session
from config import *
from switch import NetHCFSwitchBMv2
import time
from multiprocessing import Process, Manager

class NetHCFController:
    def __init__(self, iface, default_hc_list):
        self.switch = NetHCFSwitchBMv2(
            NETHCF_SWITCH_CONFIG, TARGET_THRIFT_IP, TARGET_THRIFT_PORT
        )
        # MultiProcessing Manager Instance for memory sharing
        self.mpmgr = Manager()
        self.iface = iface
        self.ip2hc = IP2HC(impact_factor_function, default_hc_list, self.mpmgr)
        self.tcp_session = TCP_Session()
        self.miss = self.mpmgr.Value('I', 0)
        self.mismatch = self.mpmgr.Value('I', 0)
        self.hcf_state = self.mpmgr.Value('B', 0) # 0: learning 1: filtering
        self.hits_bitmap = []
        self.learn_to_filter_thr = LEARN_TO_FILTER_THR
        self.filter_to_learn_thr = FILTER_TO_LEARN_THR

    def initialize(self):
        self.hcf_state.value = HCF_LEARNING_STATE
        self.switch.switch_to_learning_state()
        self.load_cache_into_switch()
        self.reset_period_counters()

    def run(self):
        self.initialize()
        self.process_packets()

    def run_parallel(self):
        self.initialize()
        update_process = Process(target=self.process_updates)
        packet_process = Process(target=self.process_packets)
        update_process.start()
        packet_process.start()
        update_process.join()
        packet_process.join()

    def process_packets(self):
        sniff(iface=self.iface, prn=self.packets_callback())

    # Nested function for passing "self" parameter to sniff's callback function
    def packets_callback(self):
        def process_function(pkt):
            if pkt[Ether].type != TYPE_IPV4:
                # This is not a IPv4 packet, ignore it temporarily
                return
            # This is a IPv4 packet
            if pkt[IP].dst == CONTROLLER_IP:
                # This is update request
                if pkt[IP].proto == TYPE_TCP:
                    # This is a write back request
                    # A SYN ACK ACK packet with replaced dst address
                    self.ip2hc.update_hc(
                        pkt[IP].src, self.compute_hc(pkt[IP].ttl)[0]
                    )
                elif pkt[IP].proto == TYPE_NETHCF:
                    # This is a cache update request
                    self.process_update_request()
            else:
                # This is the header of traffic missing IP2HC in the cache
                self.process_packets_miss_cache(pkt)
        return process_function

    def compute_hc(self, current_ttl):
        hop_count = 0
        hop_count_possible = 0
        # Select initial TTL according to current TTL, and compute HC
        if 0 <= current_ttl <= 29:
            # Initial TTL may be 30, or 32
            hop_count = 30 - current_ttl
            hop_count_possible = 32 - current_ttl
        elif 30 <= current_ttl <= 31:
            hop_count = 32 - current_ttl
            hop_count_possible = hop_count
        elif 32 <= current_ttl <= 59:
            # Initial TTL may be 60, or 64
            hop_count = 60 - current_ttl
            hop_count_possible = 64 - current_ttl
        elif 60 <= current_ttl <= 63:
            hop_count = 64 - current_ttl
            hop_count_possible = hop_count
        elif 64 <= current_ttl <= 127:
            hop_count = 128 - current_ttl
            hop_count_possible = hop_count
        else:
            hop_count = 255 - current_ttl
            hop_count_possible = hop_count
        return hop_count, hop_count_possible

    def process_packets_miss_cache(self, pkt):
        if DEBUG_OPTION:
            print("Debug: " + pkt.summary())
        hc_in_ip2hc = self.ip2hc.read_hc(pkt[IP].src)
        hop_count, hop_count_possible = self.compute_hc(pkt[IP].ttl)
        if hop_count==hc_in_ip2hc or hop_count_possible==hc_in_ip2hc:
            # Update IP2HC match statistics
            if pkt[IP].proto == TYPE_TCP and \
               pkt[TCP].flags == (FLAG_SYN | FLAG_ACK):
                self.tcp_session.update(
                    pkt[IP].dst, TCP_SESSION_IN_PROGRESS_STATE, pkt[TCP].seq
                )
            else:
                self.ip2hc.update_match_times(pkt[IP].src, 1)
            if self.hcf_state.value == HCF_FILTERING_STATE:
                sendp(pkt, iface=self.iface)
        else:
            # The HC may not be computed,
            # or the HC should be updated,
            # or this is an abnormal packet
            if pkt[IP].proto != TYPE_TCP:
                # However, we think it is abnormal traffic
                self.mismatch.value += 1
                return
            if pkt[TCP].flags == (FLAG_SYN | FLAG_ACK):
                self.tcp_session.update(
                    pkt[IP].dst, TCP_SESSION_IN_PROGRESS_STATE, pkt[TCP].seq
                )
            elif pkt[TCP].flags == FLAG_ACK:
                state, seq_no = self.tcp_session.read(pkt[IP].src)
                # This is SYN ACK ACK.
                if state == TCP_SESSION_IN_PROGRESS_STATE and \
                   pkt[TCP].ack == seq_no + 1:
                    # The connection is established
                    self.tcp_session.update(
                        pkt[IP].src, TCP_SESSION_INIT_OR_DONE_STATE, 0
                    )
                    self.ip2hc.update_hc(pkt[IP].src, hop_count)
                    # SYN, SYN ACK ACK, total two times for ip_addr(src)
                    self.ip2hc.update_match_times(pkt[IP].src, 2)
                    # Eliminate the effect of SYN
                    self.mismatch.value -= 1
                else:
                    # Abnormal packet
                    self.mismatch.value += 1
            else:
                # Such as SYN
                self.mismatch.value += 1

    def process_updates(self):
        while True:
            time.sleep(UPDATE_PERIOD)
            self.process_update_request()

    def process_update_request(self):
        self.pull_switch_counters()
        # Switch state in terms of abnormal_counter in last period
        if self.hcf_state.value == HCF_LEARNING_STATE and \
           self.mismatch.value > self.learn_to_filter_thr:
            self.hcf_state.value = HCF_FILTERING_STATE
            self.switch.switch_to_filtering_state()
        elif self.hcf_state.value == HCF_FILTERING_STATE and \
             self.mismatch.value < self.filter_to_learn_thr:
            self.hcf_state.value = HCF_LEARNING_STATE
            self.switch.switch_to_learning_state()
        elif self.hcf_state.value == HCF_LEARNING_STATE:
            self.clear_up_cache()
            update_scheme = self.ip2hc.update_cache(self.hits_bitmap)
            self.update_cache_into_switch(update_scheme)
        self.reset_period_counters()

    # Assume controller is running on the switch
    def pull_switch_counters(self):
        self.miss.value = self.switch.read_miss_counter()
        self.mismatch.value += self.switch.read_mismatch_counter()
        self.hits_bitmap = self.switch.read_hits_bitmap()
        # for idx in self.ip2hc.get_cached_index_set():
            # self.ip2hc.sync_match_times(idx, self.switch.read_hits_counter(idx))
        for idx in self.ip2hc.get_cached_index_set():
            if self.hits_bitmap[idx] == 0:
                self.ip2hc.sync_match_times(
                    idx, self.switch.read_hits_counter(idx)
                )
            else:
                self.ip2hc.sync_match_times(idx, BITMAP_ONE_TO_TIMES)

    def load_cache_into_switch(self):
        for idx in self.ip2hc.get_cached_index_set():
            ip_addr, prefix_len, hc_value = self.ip2hc.get_cached_info(idx)
            entry_handle = \
                    self.switch.add_into_ip2hc_mat(ip_addr, prefix_len, idx)
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(idx, entry_handle)
                self.switch.update_hc_value(idx, hc_value)

    def clear_up_cache(self):
        outdated_cache_items = self.ip2hc.remove_outdated_cache()
        for cache_idx in outdated_cache_items:
            self.hits_bitmap[cache_idx] = 0
            entry_handle = \
              self.ip2hc.remove_cached_item(cache_idx)[CACHE_ENTRY_HANDLE_FLAG]
            self.switch.delete_from_ip2hc_mat(entry_handle)

    def update_cache_into_switch(self, update_scheme):
        for cache_idx in update_scheme.keys():
            entry_handle = \
                    update_scheme[cache_idx][SCHEME_OLD_ENTRY_HANDLE_FLAG]
            new_ip_addr = update_scheme[cache_idx][SCHEME_NEW_IP_ADDR_FLAG]
            new_prefix_len = \
                    update_scheme[cache_idx][SCHEME_NEW_PREFIX_LEN_FLAG]
            hc_value = update_scheme[cache_idx][SCHEME_NEW_HOP_COUNT_FLAG]
            if entry_handle != NOT_DELETE_HANDLE:
                # The cache is full, replace with new item
                self.switch.delete_from_ip2hc_mat(entry_handle)
            # The cache is not full, insert new item dirctly
            entry_handle = self.switch.add_into_ip2hc_mat(
                new_ip_addr, new_prefix_len, cache_idx
            )
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(cache_idx, entry_handle)
                self.switch.update_hc_value(cache_idx, hc_value)

    def reset_period_counters(self):
        self.miss.value = 0
        self.mismatch.value = 0
        self.switch.reset_miss_counter()
        self.switch.reset_mismatch_counter()
        self.switch.reset_hits_counter()
        self.switch.reset_hits_bitmap()
        self.switch.reset_dirty_ip2hc()
        self.ip2hc.reset_last_matched()

if __name__ == "__main__":
    default_hc_list = {
        0x0A00000B: 64, 0x0A00000C: 32, 0x0A00000D: 32, 0x0A00000E: 32,\
        0x0A00000F: 32, 0x0A000010: 32, 0x0A000011: 32, 0x0A000012: 32,\
        0x0A000013: 32, 0x0A000014: 32, 0x0A000015: 32, 0x0A000016: 32,\
        0x0A000017: 32
    }
    controller = NetHCFController("s1-eth3", default_hc_list)
    # controller.run()
    controller.run_parallel()
