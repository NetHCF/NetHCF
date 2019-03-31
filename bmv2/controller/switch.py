#!/usr/bin/env python
# coding=utf-8

import os
import sys
import socket
import struct
from config import BMV2_PATH, DEBUG_OPTION

# sys.path.append(os.path.expanduser(BMV2_PATH + "/tools"))
# sys.path.append(os.path.expanduser(BMV2_PATH + "/targets/simple_switch"))

import runtime_CLI
from sswitch_runtime import SimpleSwitch
from sswitch_CLI import SimpleSwitchAPI

class NetHCFSwitchBMv2:
    def __init__(self, switch_config, thrift_ip, thrift_port):
        # Initialize own variables
        self.miss_counter = switch_config["miss_counter"]
        self.mismatch_counter = switch_config["mismatch_counter"]
        self.ip2hc_counter = switch_config["ip2hc_counter"]
        self.ip2hc_counter_bitmap = switch_config["ip2hc_counter_bitmap"]
        self.ip2hc_register = switch_config["ip2hc_register"]
        self.ip2hc_mat = switch_config["ip2hc_mat"]
        self.read_hc_function = switch_config["read_hc_function"]
        self.hcf_state = switch_config["hcf_state"]
        self.dirty_flag = switch_config["dirty_flag"]
        self.dirty_bitmap = switch_config["dirty_bitmap"]
        self.error_hint_str = (
            "Please check whether the switch "
            "is well configured and running."
        )
        # Initialize API of BMv2 runtime
        pre = runtime_CLI.PreType.SimplePreLAG
        services = runtime_CLI.RuntimeAPI.get_thrift_services(pre)
        services.extend(SimpleSwitchAPI.get_thrift_services())
        try:
            standard_client, mc_client, sswitch_client = \
                runtime_CLI.thrift_connect(thrift_ip, thrift_port, services)
        except:
            print(self.error_hint_str)
            exit(-1)
        else:
            runtime_CLI.load_json_config(standard_client)
            self.runtime_api = SimpleSwitchAPI(
                pre, standard_client, mc_client, sswitch_client
            )

    def read_register(self, register_name, index):
        return self.runtime_api.client.bm_register_read(0, register_name, index)

    def read_register_array(self, register_name):
        return self.runtime_api.client.bm_register_read_all(0, register_name)

    def reset_register(self, register_name):
        self.runtime_api.client.bm_register_reset(0, register_name)

    def write_register(self, register_name, index, value):
        self.runtime_api.client.bm_register_write(0, register_name,index,value)

    def read_counter(self, counter_name, index):
        return self.runtime_api.client.bm_counter_read(0, counter_name, index)

    def reset_counter(self, counter_name):
        self.runtime_api.client.bm_counter_reset_all(0, counter_name)

    def add_mat_entry(
        self, table_name, match_key, action_name, action_data, options
    ):
        return self.runtime_api.client.bm_mt_add_entry(
            0, table_name, match_key, action_name, action_data, options
        )

    def delete_mat_entry(self, table_name, entry_handle):
        self.runtime_api.client.bm_mt_delete_entry(0, table_name, entry_handle)

    def read_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading miss counter...")
        try:
            miss_counter = self.read_counter(self.miss_counter, 0)
            miss_counter_value = miss_counter.packets
        except:
            print("Error: Can't read miss counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: miss counter is %d." % miss_counter_value)
            return miss_counter_value

    def reset_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting miss counter...")
        try:
            self.reset_counter(self.miss_counter)
        except:
            print("Error: Can't reset miss counter!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: miss counter is resetted.")

    def read_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading mismatch counter...")
        try:
            mismatch_counter = self.read_counter(self.mismatch_counter, 0)
            mismatch_counter_value = mismatch_counter.packets
        except:
            print("Error: Can't read mismatch counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: mismatch counter is %d." % mismatch_counter_value)
            return mismatch_counter_value

    def reset_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting mismatch counter...")
        try:
            self.reset_counter(self.mismatch_counter)
        except:
            print("Error: Can't reset mismatch counter!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: mismatch counter is resetted.")

    def read_hits_counter(self, cache_idx):
        if DEBUG_OPTION:
            print(
                "Debug: reading hits counter with cache index %d..."
                % cache_idx
            )
        try:
            match_times = self.read_register(self.ip2hc_counter, cache_idx)
        except:
            print("Error: Can't read hits counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: hits counter is %d." % match_times)
            return match_times

    def reset_hits_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting hits counter...")
        try:
            self.reset_register(self.ip2hc_counter)
        except:
            print("Error: Can't reset hits counter!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: hits counter is resetted.")

    # Add entry into IP2HC Match-Action-Table
    def add_into_ip2hc_mat(self, ip_addr, prefix_len, cache_idx):
        if type(ip_addr) != str:
            ip_addr_str = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
            ip_addr_hex = struct.pack('I', socket.htonl(ip_addr))
        else:
            ip_addr_str = ip_addr
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
            ip_addr_hex = struct.pack('I', socket.htonl(ip_addr))
        mask = (2 ** prefix_len - 1) << (32 - prefix_len)
        mask_str = socket.inet_ntoa(struct.pack('I',socket.htonl(mask)))
        mask_hex = struct.pack('I', socket.htonl(mask))
        if DEBUG_OPTION:
            print(
                "Debug: adding entry of %s/%s into IP2HC-MAT at cache_idx %d..."
                % (ip_addr_str, mask_str, cache_idx)
            )
        match_key = [
            runtime_CLI.BmMatchParam(
                type=runtime_CLI.BmMatchParamType.TERNARY,
                ternary=runtime_CLI.BmMatchParamTernary(ip_addr_hex, mask_hex)
            )
        ]
        action_data = [struct.pack('B', cache_idx)]
        options = runtime_CLI.BmAddEntryOptions()
        try:
            entry_handle = self.add_mat_entry(
                self.ip2hc_mat, match_key,
                self.read_hc_function, action_data, options
            )
        except:
            print("Error: Can't add entry into IP2HC Match Action Table!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print(
                    "Debug: entry is added with entry handle %d" % entry_handle
                )
            return entry_handle

    def update_hc_value(self, cache_idx, hc_value):
        if DEBUG_OPTION:
            print(
                "Debug: Updating item with cache index %d to %d..."
                % (cache_idx, hc_value)
            )
        try:
            self.write_register(self.ip2hc_register, cache_idx, hc_value)
        except:
            print("Error: Can't write into hc value register!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: hop count register is updated")

    def delete_from_ip2hc_mat(self, entry_handle):
        if DEBUG_OPTION:
            print(
                "Debug: deleting IP2HC-MAT with entry handle %d..."
                % entry_handle
            )
        try:
            self.delete_mat_entry(self.ip2hc_mat, entry_handle)
        except:
            print("Error: Can't delete entry from IP2HC MatchActionTable!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: the entry is deleted")

    def read_hcf_state(self):
        if DEBUG_OPTION:
            print("Debug: reading hcf state in switch...")
        # Extract hcf_state from result
        try:
            hcf_state = self.read_register(self.hcf_state, 0)
        except:
            print("Error: Can't read register hcf_state!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print("Debug: readed hcf state is %d" % hcf_state)
            return hcf_state

    def switch_to_learning_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to learning...")
        try:
            self.write_register(self.hcf_state, 0, 0)
        except:
            print("Error: Can't write register hcf_state!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print("Debug: hcf state is switched to learning state.")
            return 0

    def switch_to_filtering_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to filtering...")
        try:
            self.write_register(self.hcf_state, 0, 1)
        except:
            print("Error: Can't write register hcf_state!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print("Debug: hcf state is switched to filtering state.")
            return 0

    def read_hits_bitmap(self):
        if DEBUG_OPTION:
            print("Debug: reading the bitmap for hits counter...")
        try:
            hits_bitmap = self.read_register_array(self.ip2hc_counter_bitmap)
        except:
            print("Error: Can't read the bitmap for hits counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: the bitmap for hits counter is "+str(hits_bitmap))
            return hits_bitmap

    def reset_hits_bitmap(self):
        if DEBUG_OPTION:
            print("Debug: resetting the bitmap for hits counter...")
        try:
            self.reset_register(self.ip2hc_counter_bitmap)
        except:
            print("Error: Can't reset the bitmap for hits counter!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: the bitmap for hits counter is resetted.")

    def reset_dirty_ip2hc(self):
        if DEBUG_OPTION:
            print("Debug: resetting the dirty flag...")
        try:
            self.reset_register(self.dirty_flag)
        except:
            print("Error: Can't reset the dirty flag!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: the dirty flag is resetted.")
        if DEBUG_OPTION:
            print("Debug: resetting the dirty bitmap...")
        try:
            self.reset_register(self.dirty_bitmap)
        except:
            print("Error: Can't reset the dirty bitmap!\n")
            print(self.error_hint_str)
        else:
            if DEBUG_OPTION:
                print("Debug: the dirty bitmap is resetted.")

class NetHCFSwitchBMv2CMD:
    def __init__(self, switch_config, target_switch, target_code, target_port):
        self.miss_counter = switch_config["miss_counter"]
        self.mismatch_counter = switch_config["mismatch_counter"]
        self.ip2hc_counter = switch_config["ip2hc_counter"]
        self.ip2hc_register = switch_config["ip2hc_register"]
        self.ip2hc_mat = switch_config["ip2hc_mat"]
        self.read_hc_function = switch_config["read_hc_function"]
        self.hcf_state = switch_config["hcf_state"]
        self.target_switch = target_switch
        self.target_code = target_code
        self.target_port = target_port
        self.error_hint_str = (
            "Please check whether the switch "
            "is well configured and running."
        )

    def read_miss_counter_cmd(self):
        return (
            '''echo "counter_read %s 0" | %s %s %d'''
            % (self.miss_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def read_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading miss counter...")
        result = os.popen(self.read_miss_counter_cmd()).read()
        try:
            packets_num_str = result[result.index("packets="):].split(',')[0]
            miss_counter_value = int(packets_num_str.split('=')[1])
        except:
            print("Error: Can't read miss counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: miss counter is %d" % miss_counter_value)
            return miss_counter_value

    def reset_miss_counter_cmd(self):
        return (
            '''echo "counter_reset %s" | %s %s %d'''
            % (self.miss_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def reset_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting miss counter...")
        result = os.popen(self.reset_miss_counter_cmd()).read()
        if "Done" not in result:
            print("Error: Can't reset miss counter!\n")
            print(self.error_hint_str)

    def read_mismatch_counter_cmd(self):
        return (
            '''echo "counter_read %s 0" | %s %s %d'''
            % (self.mismatch_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def read_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading mismatch counter...")
        result = os.popen(self.read_mismatch_counter_cmd()).read()
        try:
            packets_num_str = result[result.index("packets="):].split(',')[0]
            mismatch_counter_value = int(packets_num_str.split('=')[1])
        except:
            print("Error: Can't read mismatch counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: mismatch counter is %d" % mismatch_counter_value)
            return mismatch_counter_value

    def reset_mismatch_counter_cmd(self):
        return (
            '''echo "counter_reset %s" | %s %s %d'''
            % (self.mismatch_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def reset_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting mismatch counter...")
        result = os.popen(self.reset_mismatch_counter_cmd()).read()
        if "Done" not in result:
            print("Error: Can't reset mismatch counter!\n")
            print(self.error_hint_str)

    def read_hits_counter_cmd(self, cache_idx):
        return (
            '''echo "register_read %s %d" | %s %s %d'''
            % (self.ip2hc_counter, cache_idx,
               self.target_switch, self.target_code, self.target_port)
        )

    def read_hits_counter(self, cache_idx):
        if DEBUG_OPTION:
            print(
                "Debug: reading hits counter with cache index %d ..."
                % cache_idx
            )
        result = os.popen(self.read_hits_counter_cmd(cache_idx)).read()
        try:
            match_times_str = \
                result[result.index(\
                    "%s[%d]=" % (self.ip2hc_counter, cache_idx)\
                ):].split()[1]
            match_times = int(match_times_str)
        except:
            print("Error: Can't read hits counter!\n")
            print(self.error_hint_str)
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: hits counter is %d" % match_times)
            return match_times

    def reset_hits_counter_cmd(self):
        return (
            '''echo "register_reset %s" | %s %s %d'''
            % (self.ip2hc_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def reset_hits_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting hits counter...")
        result = os.popen(self.reset_hits_counter_cmd()).read()
        if "Done" not in result:
            print("Error: Can't reset hits counter!\n")
            print(self.error_hint_str)

    # Add entry into IP2HC Match-Action-Table
    def add_into_ip2hc_mat_cmd(self, ip_addr, cache_idx):
        if type(ip_addr) != str:
            ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        # # Temporary method...
        # ip_addr = ip_addr.replace('0', '10', 1)
        if DEBUG_OPTION:
            print(
                "Debug: adding entry of %s into IP2HC-MAT with cache_idx %d ..."
                % (ip_addr, cache_idx)
            )
        return (
            '''echo "table_add %s %s %s => %d" | %s %s %d'''
            % (self.ip2hc_mat, self.read_hc_function, ip_addr, cache_idx,
               self.target_switch, self.target_code, self.target_port)
        )

    def add_into_ip2hc_mat(self, ip_addr, cache_idx):
        result = os.popen(self.add_into_ip2hc_mat_cmd(ip_addr,cache_idx)).read()
        try:
            entry_handle_str = result[result.index("handle"):].split()[1]
            entry_handle = int(entry_handle_str)
        except:
            print("Error: Can't add entry into IP2HC Match Action Table!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print(
                    "Debug: entry is added with entry handle %d" % entry_handle
                )
            return entry_handle

    def update_hc_value_cmd(self, cache_idx, hc_value):
        return (
            '''echo "register_write %s %d %d" | %s %s %d'''
            % (self.ip2hc_register, cache_idx, hc_value,
               self.target_switch, self.target_code, self.target_port)
        )

    def update_hc_value(self, cache_idx, hc_value):
        if DEBUG_OPTION:
            print(
                "Debug: Updating item with cache index %d to %d ..."
                % (cache_idx, hc_value)
            )
        result = os.popen(self.update_hc_value_cmd(cache_idx, hc_value)).read()
        if "Done" not in result:
            print("Error: Can't write into hc value register!\n")
            print(self.error_hint_str)

    # Add entry into IP2HC Match-Action-Table
    def delete_from_ip2hc_mat_cmd(self, entry_handle):
        return ( '''echo "table_delete %s %d" | %s %s %d'''
            % (self.ip2hc_mat, entry_handle,
               self.target_switch, self.target_code, self.target_port)
        )

    def delete_from_ip2hc_mat(self, entry_handle):
        if DEBUG_OPTION:
            print(
                "Debug: deleting IP2HC-MAT with entry handle %d ..."
                % entry_handle
            )
        result = os.popen(self.delete_from_ip2hc_mat_cmd(entry_handle)).read()
        if "Invalid" in result:
            print("Error: Can't delete entry from IP2HC MatchActionTable!\n")
            print(self.error_hint_str)

    # Get the entry index in IP2HC-MAT
    def index_ip2hc_mat_cmd(self, ip_addr, cache_idx):
        if type(ip_addr) != str:
            ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        return (
            '''echo "table_dump_entry_from_key %s %s 0" | %s %s %d'''
            % (self.ip2hc_mat, ip_addr,
               self.target_switch, self.target_code, self.target_port)
        )

    def read_hcf_state_cmd(self):
        return (
            '''echo "register_read %s 0" | %s %s %d'''
            % (self.hcf_state,
               self.target_switch, self.target_code, self.target_port)
        )

    def read_hcf_state(self):
        if DEBUG_OPTION:
            print("Debug: reading hcf state in switch...")
        result = os.popen(self.read_hcf_state_cmd()).read()
        # Extract hcf_state from result
        try:
            hcf_state_str = \
                    result[result.index("%s[0]=" % self.hcf_state):].split()[1]
            hcf_state = int(hcf_state_str)
        except:
            print("Error: Can't read register hcf_state!\n")
            print(self.error_hint_str)
            return -1
        else:
            if DEBUG_OPTION:
                print("Debug: readed hcf state is %d" % hcf_state)
            return hcf_state

    def switch_to_learning_state_cmd(self):
        return (
            '''echo "register_write %s 0 0" | %s %s %d'''
            % (self.hcf_state,
               self.target_switch, self.target_code, self.target_port)
        )

    def switch_to_learning_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to learning...")
        result = os.popen(self.switch_to_learning_state_cmd()).read()
        if "Done" in result:
            return 0
        else:
            print("Error: Can't write register hcf_state!\n")
            print(self.error_hint_str)
            return -1

    def switch_to_filtering_state_cmd(self):
        return (
            '''echo "register_write %s 0 1" | %s %s %d'''
            % (self.hcf_state,
               self.target_switch, self.target_code, self.target_port)
        )

    def switch_to_filtering_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to filtering...")
        result = os.popen(self.switch_to_filtering_state_cmd()).read()
        if "Done" in result:
            return 0
        else:
            print("Error: Can't write register hcf_state!\n")
            print(self.error_hint_str)
            return -1

