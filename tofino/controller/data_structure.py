#!/usr/bin/env python
# coding=utf-8

import sys
import heapq
import struct
import socket
from array import array
from config import *


class ImpactHeap:
    # item: [impact_factor, ip_addr]
    def __init__(self, impact_factor_function):
        self._heap = []
        self.impact_factor_function = impact_factor_function

    def push(self, ip_addr, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        # -1 is because we want use heapq to realize large heap
        impact_factor *= -1
        item = [impact_factor, ip_addr]
        heapq.heappush(self._heap, item)
        return item

    def push_direct(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, item_pointer, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        item_pointer[0] = -1 * impact_factor
        heapq.heapify(self._heap)

    def reorgnize(self):
        heapq.heapify(self._heap)


class CacheHeap:
    # item: [impact_factor, ip_addr, idx, entry_handle]
    def __init__(self, impact_factor_function):
        self._heap = []
        self.impact_factor_function = impact_factor_function

    def push(self, ip_addr, idx, entry_handle, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        # -1 is because we want use heapq to realize large heap
        item = [impact_factor, ip_addr, idx, entry_handle]
        heapq.heappush(self._heap, item)
        return item

    def push_direct(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, item_pointer, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        item_pointer[0] = impact_factor
        heapq.heapify(self._heap)

    def reorgnize(self):
        heapq.heapify(self._heap)


class IP2HC:
    def __init__(self, impact_factor_function, default_hc_list):
        # Count of the ip-hc pairs in IP2HC table
        self.count = 0
        # Length of bits to devide ip address pertime
        self.devide_bits = DEVIDE_BITS
        if 32 % self.devide_bits != 0:
            print(
                "Warning: Please check DEVIDE_BITS in "
                "config.py and select from [2, 4, 8, 16]"
            )
        # A tree-like structure to map ip address to index
        self.ip2idx = {}
        # Init the Impact Heap of the IP2HC
        self.impact_heap = ImpactHeap(impact_factor_function)
        # Init the Cache Heap of the switch
        self.cache_heap = CacheHeap(impact_factor_function)
        # Init each column of the IP2HC table
        self.hc_value = array('B', [])
        print("HC Value List Size: %d" % sys.getsizeof(self.hc_value))
        self.total_matched = array('H', [])
        print("Total Matched List Size: %d" % sys.getsizeof(self.total_matched))
        self.last_matched = array('B', [])
        print("Last Matched List Size: %d" % sys.getsizeof(self.last_matched))
        # self.heap_pointer = [
            # self.impact_heap.push(ip_addr, 0, 0) 
            # for ip_addr in range(IP_SPACE_SIZE)
        # ]
        self.heap_pointer = []
        print("Heap Pointer List Size: %d" % sys.getsizeof(self.heap_pointer))
        self.cache = []
        print("Cache List Size: %d" % sys.getsizeof(self.cache))
        # Load the default_hc_list into IP2HC and cache
        if len(default_hc_list) > CACHE_SIZE:
            print "Warning: the cache cannot hold the whole default_hc_list"
        for ip_addr in default_hc_list.keys():
            hc_value = default_hc_list[ip_addr]
            cache_idx = len(self.cache)
            # Load into IP2HC
            ip2hc_idx = self.add_into_ip2hc(ip_addr, hc_value)
            # Load into cache
            self.cache.append(
                self.cache_heap.push(ip_addr, cache_idx, cache_idx, 0, 0)
            )
            self.heap_pointer[ip2hc_idx][0] = 0

    def add_into_ip2hc(self, ip_addr, hc_value):
        mask = (1 << self.devide_bits) - 1
        local_ip2idx = self.ip2idx
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - 8 * (i + 1))) & mask
            if i == devide_steps - 1:
                # Last level
                if ip_addr_part in local_ip2idx.keys():
                    self.hc_value[local_ip2idx[ip_addr_part]] = hc_value
                else:
                    local_ip2idx[ip_addr_part] = self.count
                    self.count += 1
                    self.hc_value.append(hc_value)
                    self.last_matched.append(0)
                    self.total_matched.append(0)
                    self.heap_pointer.append(
                        self.impact_heap.push(ip_addr, 0, 0)
                    )
            else:
                if ip_addr_part in local_ip2idx.keys():
                    local_ip2idx = local_ip2idx[ip_addr_part]
                else:
                    local_ip2idx[ip_addr_part] = {}
                    local_ip2idx = local_ip2idx[ip_addr_part]
        # Return the ip2hc_idx
        return self.count - 1

    def get_idx_for_ip(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2idx = self.ip2idx
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if ip_addr_part in local_ip2idx.keys():
                    return local_ip2idx[ip_addr_part]
                else:
                    return -1
            else:
                if ip_addr_part in local_ip2idx.keys():
                    local_ip2idx = local_ip2idx[ip_addr_part]
                else:
                    return -1
        return -1

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        ip2hc_idx = self.get_idx_for_ip(ip_addr)
        if ip2hc_idx == -1:
            return DEFAULT_HC
        else:
            return self.hc_value[ip2hc_idx]

    def hit_in_controller(self, ip_addr, times):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        ip2hc_idx = self.get_idx_for_ip(ip_addr)
        if ip2hc_idx == -1:
            print "Error: can't find info for this ip %d in IP2HC" % ip_addr
            return -1
        else:
            self.last_matched[ip2hc_idx] += times
            self.total_matched[ip2hc_idx] += times
            self.impact_heap.update(
                self.heap_pointer[ip2hc_idx], 
                self.total_matched[ip2hc_idx], self.last_matched[ip2hc_idx]
            )
            return 0

    def update(self, ip_addr, hc_value):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        ip2hc_idx = self.get_idx_for_ip(ip_addr)
        if ip2hc_idx == -1:
            self.add_into_ip2hc(ip_addr, hc_value)
        else:
            self.hc_value[ip2hc_idx] = hc_value

    
    def sync_match_times(self, cache_idx, times):
        ip_addr = self.cache[cache_idx][1]
        ip2hc_idx = self.get_idx_for_ip(ip_addr)
        if ip2hc_idx == -1:
            print "Error: can't find info for this ip %d in IP2HC" % ip_addr
            return -1
        else:
            self.last_matched[ip2hc_idx] += times
            self.total_matched[ip2hc_idx] += times
            self.cache_heap.update(
                self.cache[cache_idx], 
                self.total_matched[ip2hc_idx], self.last_matched[ip2hc_idx]
            )

    def get_cached_size(self):
        return len(self.cache)

    def get_cached_info(self, cache_idx):
        ip_addr = self.cache[cache_idx][1]
        # print len(self.hc_value), ip_addr
        ip2hc_idx = self.get_idx_for_ip(ip_addr)
        if ip2hc_idx == -1:
            print "Error: can't find info for this ip %d in IP2HC" % ip_addr
            return -1, DEFAULT_HC
        else:
            hc_value = self.hc_value[ip2hc_idx]
        return ip_addr, hc_value

    def update_cache(self, miss_counter):
        count = number_to_be_replaced(miss_counter)
        cache_list_to_replace = []
        controller_list_to_replace = []
        update_scheme = {}
        # scheme structure: {cache_idx: (old_ip, new_ip, new_hc)}
        load_directly = CACHE_SIZE - len(self.cache)
        # Select count item to be replaced
        if DEBUG_OPTION:
            print(
                "Debug: Decide to add or replace %d cache entries ..." % count
            )
        if count <= load_directly:
            for i in range(count):
                controller_item = self.impact_heap.pop()
                if controller_item[0] == 0.0:
                    # Also in cache
                    self.impact_heap.push_direct(controller_item)
                else:
                    ip_addr = controller_item[1]
                    ip2hc_idx = self.get_idx_for_ip(ip_addr)
                    cache_idx = len(self.cache)
                    self.cache.append(
                        self.cache_heap.push(
                            ip_addr, cache_idx, cache_idx, 
                            self.total_matched[ip2hc_idx], 
                            self.last_matched[ip2hc_idx]
                        )
                    )
                    controller_item[0] = 0
                    self.impact_heap.push_direct(controller_item)
                    update_scheme[cache_idx] = \
                            (0, ip_addr, self.hc_value[ip2hc_idx])
        else:
            for i in range(count - load_directly):
                controller_list_to_replace.append(self.impact_heap.pop())
                cache_list_to_replace.append(self.cache_heap.pop())
            for i in range(load_directly):
                controller_item = self.impact_heap.pop()
                if controller_item[0] == 0.0:
                    # Also in cache
                    self.impact_heap.push_direct(controller_item)
                else:
                    ip_addr = controller_item[1]
                    ip2hc_idx = self.get_idx_for_ip(ip_addr)
                    cache_idx = len(self.cache)
                    self.cache.append(
                        self.cache_heap.push(
                            ip_addr, cache_idx, cache_idx, 
                            self.total_matched[ip2hc_idx], 
                            self.last_matched[ip2hc_idx]
                        )
                    )
                    controller_item[0] = 0
                    self.impact_heap.push_direct(controller_item)
                    update_scheme[cache_idx] = \
                            (0, ip_addr, self.hc_value[ip2hc_idx])
            for i in range(count - load_directly):
                cache_item = cache_list_to_replace[i]
                controller_item = controller_list_to_replace[i]
                old_ip_addr = cache_item[1]
                cache_idx = cache_item[2]
                entry_handle = cache_item[3]
                old_ip_ip2hc_idx = self.get_idx_for_ip(old_ip_addr)
                new_ip_addr = controller_item[1]
                new_ip_ip2hc_idx = self.get_idx_for_ip(new_ip_addr)
                if new_ip_ip2hc_idx == -1 or old_ip_ip2hc_idx == -1:
                    print(
                        "Error: can't find info for this ip "
                        "%d, %d in IP2HC" % (new_ip_addr, old_ip_addr)
                    )
                    return {}
                # Push new item from controller into cache
                self.cache[cache_idx] = self.cache_heap.push(
                    new_ip_addr, cache_idx, entry_handle, 
                    self.total_matched[new_ip_ip2hc_idx], 
                    self.last_matched[new_ip_ip2hc_idx]
                )
                # Set the impact factor of thoes pushed into cache to 0
                controller_item[0] = 0
                self.impact_heap.push_direct(controller_item)
                # update_scheme[cache_idx] = \
                    # (entry_handle, new_ip_addr, self.hc_value[new_ip_addr])
                update_scheme[cache_idx] = \
                    (old_ip_addr, new_ip_addr, self.hc_value[new_ip_ip2hc_idx])
                # Set the impact factor of those from cache to normal
                self.impact_heap.update(
                    self.heap_pointer[old_ip_ip2hc_idx],
                    self.total_matched[old_ip_ip2hc_idx], 
                    self.last_matched[old_ip_ip2hc_idx]
                )
        return update_scheme

    def reset_last_matched(self):
        self.last_matched = array('B', [0 for i in range(self.count)])

    def update_entry_handle_in_cache(self, cache_idx, entry_handle):
        self.cache[cache_idx][3] = entry_handle

class TCP_Session:
    def __init__(self):
        self.state = array('B', [0 for ip_addr in range(IP_SPACE_SIZE)])
        self.seq_number = array('I', [0 for ip_addr in range(IP_SPACE_SIZE)])
        print("TCP State List Size: %d" % sys.getsizeof(self.state))
        print("TCP SEQ Number List Size: %d" % sys.getsizeof(self.seq_number))

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        # Temporary method
        ip_addr = ip_addr & (IP_SPACE_SIZE - 1)
        return self.state[ip_addr], self.seq_number[ip_addr]

    def update(self, ip_addr, state, seq_number):
        # print "\n\nDebug: ip %s\n\n" % ip_addr
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        # print "\n\nDebug: ip %d\n\n" % ip_addr
        # Temporary method
        ip_addr = ip_addr & (IP_SPACE_SIZE - 1)
        self.state[ip_addr] = state
        self.seq_number[ip_addr] = seq_number

