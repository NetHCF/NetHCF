#!/usr/bin/env python
# coding=utf-8

from scapy.all import *
from data_structure import IP2HC, TCP_Session
from config import *
# from switch import NetHCFSwitchBMv2
from switch_interface import NetHCFSwitchTofino
import time
from multiprocessing import Process

class NetHCFController:
    def __init__(self, iface, default_hc_list):
        # self.switch = NetHCFSwitchBMv2(
            # NETHCF_SWITCH_CONFIG, TARGET_SWITCH, TARGET_CODE, TARGET_PORT
        # )
        self.switch = NetHCFSwitchTofino(NETHCF_SWITCH_CONFIG, DP_CONFIG)
        self.iface = iface
        self.ip2hc = IP2HC(impact_factor_function, default_hc_list);
        self.tcp_session = TCP_Session()
        self.miss = 0
        self.mismatch = 0
        self.hcf_state = 0 # 0: learning 1: filtering
        self.learn_to_filter_thr = LEARN_TO_FILTER_THR
        self.filter_to_learn_thr = FILTER_TO_LEARN_THR

    def initialize(self):
        self.hcf_state = 0
        self.switch.initialize()
        self.switch.switch_to_learning_state()
        self.load_cache_into_switch()
        self.reset_period_counters()

    def run(self):
        # self.initialize()
        self.process_packets()

    def run_parallel(self):
        self.initialize()
        packet_process = Process(target=self.process_packets, )
        update_process = Process(target=self.process_updates, args=(5,))
        packet_process.start()
        update_process.start()

    def process_packets(self):
        while True:
            if self.hcf_state == 0:
                digest = self.switch.get_digest()
                if len(digest.msg) == 0:
                    continue
                # else:
                    # print digest.msg
                for digest_entry in digest.msg:
                    self.process_packets_digest(digest_entry)
                self.switch.notify_digest(digest.msg_ptr)
            elif self.hcf_state == 1:
                sniff(
                    iface=self.iface, count=FILTERING_BATCH,
                    prn=self.packets_callback()
                )

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
                    self.ip2hc.update(
                        pkt[IP].src,
                        self.compute_hc(pkt[IP])
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
            hop_count = 127 - current_ttl
            hop_count_possible = hop_count
        else:
            hop_count = 255 - current_ttl
            hop_count_possible = hop_count
        return hop_count, hop_count_possible

    def process_packets_miss_cache(self, pkt):
        # # Temporary method
        # pkt[IP].src = pkt[IP].src.replace("10", "0", 1)
        # pkt[IP].dst = pkt[IP].dst.replace("10", "0", 1)
        if DEBUG_OPTION:
            print "Debug: " + pkt.summary()
        hc_in_ip2hc = self.ip2hc.read(pkt[IP].src)
        hop_count, hop_count_possible = self.compute_hc(pkt[IP].ttl)
        if hop_count==hc_in_ip2hc or hop_count_possible==hc_in_ip2hc:
            # Update IP2HC match statistics
            if pkt[IP].proto == TYPE_TCP and \
               pkt[TCP].flags == (FLAG_SYN | FLAG_ACK):
                self.tcp_session.update(pkt[IP].dst, 1, pkt[TCP].seq)
            else:
                self.ip2hc.hit_in_controller(pkt[IP].src, 1)
            if self.hcf_state == 1:
                sendp(pkt, iface=self.iface)
        else:
            # The HC may not be computed,
            # or the HC should be updated,
            # or this is an abnormal packet
            if pkt[IP].proto != TYPE_TCP:
                # However, we think it is abnormal traffic
                self.mismatch += 1
                return
            if pkt[TCP].flags == (FLAG_SYN | FLAG_ACK):
                self.tcp_session.update(pkt[IP].dst, 1, pkt[TCP].seq)
            elif pkt[TCP].flags == FLAG_ACK:
                state, seq_no = self.tcp_session.read(pkt[IP].src)
                # This is SYN ACK ACK.
                if state == 1 and pkt[TCP].ack == seq_no + 1:
                    # The connection is established
                    self.tcp_session.update(pkt[IP].src, 0, 0)
                    self.ip2hc.update(pkt[IP].src, hop_count)
                    # SYN, SYN ACK ACK, total two times for ip_addr(src)
                    self.ip2hc.hit_in_controller(pkt[IP].src, 2)
                    # Eliminate the effect of SYN
                    self.mismatch -= 1
                else:
                    # Abnormal packet
                    self.mismatch += 1
            else:
                # Such as SYN
                self.mismatch += 1

    def process_packets_digest(self, digest_entry):
        # Temporary method
        # pkt[IP].src = pkt[IP].src.replace("10", "0", 1)
        # pkt[IP].dst = pkt[IP].dst.replace("10", "0", 1)
        # digest_entry.ipv4_srcAddr = digest_entry.ipv4_srcAddr & 255
        # digest_entry.meta_dstAddr = digest_entry.meta_dstAddr & 255
        digest_entry.ipv4_srcAddr = self.switch.convert_to_unsigned(
            digest_entry.ipv4_srcAddr, 32
        )
        digest_entry.meta_dstAddr = self.switch.convert_to_unsigned(
            digest_entry.meta_dstAddr, 32
        )
        digest_entry.tcp_seqNo = self.switch.convert_to_unsigned(
            digest_entry.tcp_seqNo, 32
        )
        digest_entry.tcp_ackNo = self.switch.convert_to_unsigned(
            digest_entry.tcp_ackNo, 32
        )
        ip_src = digest_entry.ipv4_srcAddr
        ip_dst = digest_entry.meta_dstAddr
        ip_ttl = digest_entry.ipv4_ttl
        ip_protocol = digest_entry.ipv4_protocol
        tcp_seq = digest_entry.tcp_seqNo
        tcp_ack = digest_entry.tcp_ackNo
        tcp_flags = digest_entry.tcp_urg << 5 | digest_entry.tcp_ack << 4| \
                    digest_entry.tcp_psh << 3 | digest_entry.tcp_rst << 2| \
                    digest_entry.tcp_syn << 1 | digest_entry.tcp_fin
        # if ip_dst == CONTROLLER_IP:
        if ip_dst == struct.unpack('!I', socket.inet_aton(CONTROLLER_IP))[0]:
            # This is update request
            if ip_protocol == TYPE_TCP:
                # This is a write back request
                # A SYN ACK ACK packet with replaced dst address
                self.ip2hc.update(ip_src, self.compute_hc(ip_ttl)[0])
            elif 256+ip_protocol == TYPE_NETHCF:
                # This is a cache update request
                self.process_update_request()
        else:
            # This is the header of traffic missing IP2HC in the cache
            hc_in_ip2hc = self.ip2hc.read(ip_src)
            hop_count, hop_count_possible = self.compute_hc(ip_ttl)
            if hop_count==hc_in_ip2hc or hop_count_possible==hc_in_ip2hc:
                # Update IP2HC match statistics
                if ip_protocol == TYPE_TCP and \
                   tcp_flags == (FLAG_SYN | FLAG_ACK):
                    self.tcp_session.update(ip_dst, 1, tcp_seq)
                else:
                    self.ip2hc.hit_in_controller(ip_src, 1)
                if self.hcf_state == 1:
                    sendp(pkt, iface=self.iface)
            else:
                # The HC may not be computed,
                # or the HC should be updated,
                # or this is an abnormal packet
                if ip_protocol != TYPE_TCP:
                    # However, we think it is abnormal traffic
                    self.mismatch += 1
                    return
                if tcp_flags == (FLAG_SYN | FLAG_ACK):
                    print "Debug: ip_dst %d tcp_seq %d" % (ip_dst, tcp_seq)
                    self.tcp_session.update(ip_dst, 1, tcp_seq)
                elif tcp_flags == FLAG_ACK:
                    state, seq_no = self.tcp_session.read(ip_src)
                    # This is SYN ACK ACK.
                    if state == 1 and tcp_ack == seq_no + 1:
                        # The connection is established
                        self.tcp_session.update(ip_src, 0, 0)
                        self.ip2hc.update(ip_src, hop_count)
                        print(
                            "Debug: connection established ip "
                            "%d hop_count % d" % (ip_src, hop_count)
                        )
                        # SYN, SYN ACK ACK, total two times for ip_addr(src)
                        self.ip2hc.hit_in_controller(ip_src, 2)
                        # Eliminate the effect of SYN
                        self.mismatch -= 1
                    else:
                        # Abnormal packet
                        self.mismatch += 1
                else:
                    # Such as SYN
                    self.mismatch += 1
        if DEBUG_OPTION:
            print "Debug: " + str(digest_entry)

    def process_updates(self, period):
        while True:
            self.process_update_request()
            time.sleep(period)

    def process_update_request(self):
        self.pull_switch_counters()
        # Switch state in terms of abnormal_counter in last period
        if self.hcf_state == 0 and self.mismatch > self.learn_to_filter_thr:
            self.hcf_state = 1
            self.switch.switch_to_filtering_state()
        elif self.hcf_state == 1 and self.mismatch < self.filter_to_learn_thr:
            self.hcf_state = 0
            self.switch.switch_to_learning_state()
        elif self.hcf_state == 0:
            update_scheme = self.ip2hc.update_cache(self.miss)
            self.update_cache_into_switch(update_scheme)
        self.reset_period_counters()

    # Assume controller is running on the switch
    def pull_switch_counters(self):
        self.miss = self.switch.read_miss_counter()
        self.mismatch += self.switch.read_mismatch_counter()
        for idx in range(self.ip2hc.get_cached_size()):
            self.ip2hc.sync_match_times(idx, self.switch.read_hits_counter(idx))

    def load_cache_into_switch(self):
        for idx in range(self.ip2hc.get_cached_size()):
            ip_addr, hc_value = self.ip2hc.get_cached_info(idx)
            entry_handle = self.switch.add_into_ip2hc_mat(ip_addr, idx)
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(idx, entry_handle)
                self.switch.update_hc_value(idx, hc_value)

    def update_cache_into_switch(self, update_scheme):
        for cache_idx in update_scheme.keys():
            old_ip_addr = update_scheme[cache_idx][0]
            new_ip_addr = update_scheme[cache_idx][1]
            hc_value = update_scheme[cache_idx][2]
            if entry_handle !=0:
                self.switch.delete_from_ip2hc_mat(old_ip_addr)
            entry_handle = self.switch.add_into_ip2hc_mat(new_ip_addr,cache_idx)
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(cache_idx, entry_handle)
                self.switch.update_hc_value(cache_idx, hc_value)

    def reset_period_counters(self):
        self.miss = 0
        self.mismatch = 0
        self.switch.reset_miss_counter()
        self.switch.reset_mismatch_counter()
        self.switch.reset_hits_counter()
        self.ip2hc.reset_last_matched()

if __name__ == "__main__":
    controller = NetHCFController("veth251", {0x0A00000B: 64})
    # controller.run()
