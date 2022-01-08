#!/usr/bin/env python
# coding=utf-8

import logging
import os
import pd_base_tests
import pltfm_pm_rpc
import pal_rpc
import random
import sys
import time
import unittest

from nethcf.p4_pd_rpc.ttypes import *
from pltfm_pm_rpc.ttypes import *
from pal_rpc.ttypes import *
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from res_pd_rpc.ttypes import *

import os
import socket
import struct
from config import DEBUG_OPTION

class NetHCFSwitchTofino:
    def __init__(self, switch_config, dp_config):
        self.project_name = switch_config["project_name"]
        self.digest_fields = switch_config["digest_fields"]
        self.miss_counter = switch_config["miss_counter"]
        self.mismatch_counter = switch_config["mismatch_counter"]
        self.ip2hc_counter = switch_config["ip2hc_counter"]
        self.ip2hc_register = switch_config["ip2hc_register"]
        self.ip2hc_mat = switch_config["ip2hc_mat"]
        self.read_hc_function = switch_config["read_hc_function"]
        self.hcf_state = switch_config["hcf_state"]
        self.error_hint_str = (
            "Please check whether the switch is well "
            "configured and the program is well compiled."
        )
        self.dp_intfc = dp_config["dp_interface"] # Data plane interface
        self.dp_intfc_func = {}
        self.dp_intfc_spec = {}
        self.generate_dp_intfc_functions()
        self.generate_dp_intfc_specifications()
        self.dp_config = dp_config

    def initialize(self):
        # Analogy to loading "commands.txt" in bmv2
        # "table_set_default ..."
        for mat_table in self.dp_config["set_default"].keys():
            item = self.dp_config["set_default"][mat_table]
            action = item["action"]
            if hasattr(
                self.dp_intfc, "%s_set_default_action_%s" % (mat_table,action)
            ):
                if item["parameter"][0] == 0:
                    result = getattr(
                        self.dp_intfc,
                        "%s_set_default_action_%s" % (mat_table, action)
                    )(self.dp_config["sess_hdl"], self.dp_config["dev_tgt"])
                elif item["parameter"][0] == 1:
                    try:
                        eval("%s_%s_action_spec_t" % (self.project_name,action))
                    except NameError:
                        print(
                            "Error: Can't find specification of action %s for "
                            "%s in the data plane interface!"%(action,mat_table)
                        )
                        print self.error_hint_str
                    else:
                        action_spec = eval(
                            "%s_%s_action_spec_t" % (self.project_name, action)
                        )(item["parameter"][1])
                        result = getattr(
                            self.dp_intfc,
                            "%s_set_default_action_%s" % (mat_table, action)
                        )(
                            self.dp_config["sess_hdl"],
                            self.dp_config["dev_tgt"], action_spec
                        )
                if DEBUG_OPTION:
                    print(
                        "Debug: set default action %s for "
                        "%s success" % (action, mat_table)
                    )
                    print(
                        "Debug: now %d entries exist in %s" % (result,mat_table)
                    )
            else:
                print(
                    "Error: Can't find set_default function for %s "
                    "in the data plane interface!" % mat_table
                )
                print self.error_hint_str
        # "table_add ..."
        for item in self.dp_config["table_add"]:
            mat_table = item["table"]
            action = item["action"]
            try:
                eval("%s_%s_match_spec_t" % (self.project_name, mat_table))
            except NameError:
                print(
                    "Error: Can't find match specification for "
                    "%s in the data plane interface!" % mat_table
                )
                print self.error_hint_str
            else:
                if hasattr(
                    self.dp_intfc, "%s_table_add_with_%s" % (mat_table, action)
                ):
                    priority_flag = False
                    if item["match"][0] == 1 and item["match"][1] == "exact":
                        match_spec = eval(
                            "%s_%s_match_spec_t" % (self.project_name,mat_table)
                        )(item["match"][2])
                    elif item["match"][0] == 1 and item["match"][1] == "range":
                        match_spec = eval(
                            "%s_%s_match_spec_t" % (self.project_name,mat_table)
                        )(item["match"][2][0], item["match"][2][1])
                        priority_flag = True
                    elif item["match"][0] == 2 and item["match"][1] == "exact" \
                            and item["match"][3] == "exact":
                        match_spec = eval(
                            "%s_%s_match_spec_t" % (self.project_name,mat_table)
                        )(item["match"][2], item["match"][4])
                    if item["parameter"][0] == 0:
                        if priority_flag:
                            result = getattr(
                                self.dp_intfc,
                                "%s_table_add_with_%s" % (mat_table, action)
                            )(
                                self.dp_config["sess_hdl"],
                                self.dp_config["dev_tgt"],
                                match_spec, item["priority"]
                            )
                        else:
                            result = getattr(
                                self.dp_intfc,
                                "%s_table_add_with_%s" % (mat_table, action)
                            )(
                                self.dp_config["sess_hdl"],
                                self.dp_config["dev_tgt"], match_spec
                            )
                    elif item["parameter"][0] == 1:
                        try:
                            eval("%s_%s_action_spec_t" \
                                 % (self.project_name, action))
                        except NameError:
                            print(
                                "Error: Can't find specification of action %s "
                                "or match for %s in the data plane interface!" \
                                % (action, mat_table)
                            )
                            print self.error_hint_str
                        else:
                            action_spec = eval(
                                "%s_%s_action_spec_t"%(self.project_name,action)
                            )(item["parameter"][1])
                            if priority_flag:
                                result = getattr(
                                    self.dp_intfc,
                                    "%s_table_add_with_%s" % (mat_table, action)
                                )(
                                    self.dp_config["sess_hdl"],
                                    self.dp_config["dev_tgt"],
                                    match_spec, item["priority"], action_spec
                                )
                            else:
                                result = getattr(
                                    self.dp_intfc,
                                    "%s_table_add_with_%s" % (mat_table, action)
                                )(
                                    self.dp_config["sess_hdl"],
                                    self.dp_config["dev_tgt"],
                                    match_spec, action_spec
                                )
                    if DEBUG_OPTION:
                        print("Debug: table add for %s success" % mat_table)
                        print(
                            "Debug: now %d entries exist in "
                            "%s" % (result, mat_table)
                        )
                else:
                    print "%s_table_add_with_%s" % (mat_table, action)
                    print(
                        "Error: Can't find table add function for %s "
                        "in the data plane interface!" % mat_table
                    )
                    print self.error_hint_str
        # Register digest
        self.register_digest()

    def generate_dp_intfc_functions(self):
        # For register_array, key is register name in controller
        # while value is its name in data plane
        # Notice that the counters in bmv2 version
        # is implemented by registers in tofino
        register_array = {
            "miss_counter": self.miss_counter,
            "mismatch_counter": self.mismatch_counter,
            "ip2hc_counter": self.ip2hc_counter,
            "ip2hc_register": self.ip2hc_register,
            "hcf_state": self.hcf_state
        }
        # read, write and reset function for registers
        for ctrl_reg in register_array.keys():
            dp_reg = register_array[ctrl_reg]
            self.dp_intfc_func[ctrl_reg] = {}
            # register_read function
            if hasattr(self.dp_intfc, "register_read_%s" % dp_reg):
                self.dp_intfc_func[ctrl_reg]["read"] = \
                        "register_read_%s" % dp_reg
            else:
                print(
                    "Error: Can't find read function for "
                    "%s in the data plane interface!" % ctrl_reg
                )
                print self.error_hint_str
            # register_write function
            if hasattr(self.dp_intfc, "register_write_%s" % dp_reg):
                self.dp_intfc_func[ctrl_reg]["write"] = \
                        "register_write_%s" % dp_reg
            else:
                print(
                    "Error: Can't find write function for "
                    "%s in the data plane interface!" % ctrl_reg
                )
                print self.error_hint_str
            # register_reset function
            if hasattr(self.dp_intfc, "register_reset_all_%s" % dp_reg):
                self.dp_intfc_func[ctrl_reg]["reset"] = \
                        "register_reset_all_%s" % dp_reg
            else:
                print(
                    "Error: Can't find reset function for "
                    "%s in the data plane interface!" % ctrl_reg
                )
                print self.error_hint_str
        # add and delete function for IP2HC-MAT
        self.dp_intfc_func["ip2hc_mat"] = {}
        if hasattr(
            self.dp_intfc,
            "%s_table_add_with_%s" % (self.ip2hc_mat, self.read_hc_function)
        ):
            self.dp_intfc_func["ip2hc_mat"]["add"] = \
                "%s_table_add_with_%s" % (self.ip2hc_mat, self.read_hc_function)
        else:
            print(
                "Error: Can't find add function for "
                "IP2HC-MAT in the data plane interface!"
            )
            print self.error_hint_str
        if hasattr(
            self.dp_intfc, "%s_table_delete_by_match_spec" % self.ip2hc_mat
        ):
            self.dp_intfc_func["ip2hc_mat"]["delete"] = \
                "%s_table_delete_by_match_spec" % self.ip2hc_mat
        else:
            print(
                "Error: Can't find add function for "
                "IP2HC-MAT in the data plane interface!"
            )
            print self.error_hint_str
        # digest get, register, notify
        self.dp_intfc_func["digest_fields"] = {}
        if hasattr(self.dp_intfc, "%s_get_digest" % self.digest_fields):
            self.dp_intfc_func["digest_fields"]["get"] = \
                    "%s_get_digest" % self.digest_fields
        else:
            print(
                "Error: Can't find get function for "
                "digest_fields in the data plane interface!"
            )
            print self.error_hint_str
        if hasattr(self.dp_intfc, "%s_register" % self.digest_fields):
            self.dp_intfc_func["digest_fields"]["register"] = \
                    "%s_register" % self.digest_fields
        else:
            print(
                "Error: Can't find register function for "
                "digest_fields in the data plane interface!"
            )
            print self.error_hint_str
        if hasattr(self.dp_intfc, "%s_digest_notify_ack" % self.digest_fields):
            self.dp_intfc_func["digest_fields"]["notify"] = \
                    "%s_digest_notify_ack" % self.digest_fields
        else:
            print(
                "Error: Can't find notify function for "
                "digest_fields in the data plane interface!"
            )
            print self.error_hint_str

    def generate_dp_intfc_specifications(self):
        self.dp_intfc_spec["ip2hc_mat"] = {}
        # Specification for IP2HC-MAT match item
        try:
            eval("%s_%s_match_spec_t" % (self.project_name, self.ip2hc_mat))
        except NameError:
            print(
                "Error: Can't find match specification for "
                "IP2HC-MAT in the data plane interface!"
            )
            print self.error_hint_str
        else:
            self.dp_intfc_spec["ip2hc_mat"]["match"] = \
                    "%s_%s_match_spec_t" % (self.project_name, self.ip2hc_mat)
        # Specification for IP2HC-MAT action item
        try:
            eval(
                "%s_%s_action_spec_t" \
                % (self.project_name, self.read_hc_function)
            )
        except NameError:
            print(
                "Error: Can't find action specification for "
                "IP2HC-MAT in the data plane interface!"
            )
            print self.error_hint_str
        else:
            self.dp_intfc_spec["ip2hc_mat"]["action"] = \
                    "%s_%s_action_spec_t"  \
                    % (self.project_name, self.read_hc_function)


    def read_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading miss counter...")
        function_name = self.dp_intfc_func["miss_counter"]["read"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            0, self.dp_config["hw_sync_flag"]
        )
        return sum(result)
        # Extracting info from the result is to be verified

    def reset_miss_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting miss counter...")
        function_name = self.dp_intfc_func["miss_counter"]["reset"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"]
        )
        if result is not None:
            print "Error: maybe wrong in reset_miss_counter"
        # Extracting info from the result is to be verified

    def read_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: reading mismatch counter...")
        function_name = self.dp_intfc_func["mismatch_counter"]["read"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            0, self.dp_config["hw_sync_flag"]
        )
        return sum(result)
        # Extracting info from the result is to be verified

    def reset_mismatch_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting mismatch counter...")
        function_name = self.dp_intfc_func["miss_counter"]["reset"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"]
        )
        if result is not None:
            print "Error: maybe wrong in reset_mismatch_counter"
        # Extracting info from the result is to be verified

    def read_hits_counter(self, cache_idx):
        if DEBUG_OPTION:
            print(
                "Debug: reading hits counter with cache index %d ..."
                % cache_idx
            )
        function_name = self.dp_intfc_func["ip2hc_counter"]["read"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            cache_idx, self.dp_config["hw_sync_flag"]
        )
        return sum(result)
        # Extracting info from the result is to be verified

    def reset_hits_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting hits counter...")
        function_name = self.dp_intfc_func["mismatch_counter"]["reset"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"]
        )
        if result is not None:
            print "Error: maybe wrong in reset_hits_counter"
        # Extracting info from the result is to be verified

    def update_hc_value(self, cache_idx, hc_value):
        if DEBUG_OPTION:
            print(
                "Debug: Updating item with cache index %d to %d ..."
                % (cache_idx, hc_value)
            )
        function_name = self.dp_intfc_func["ip2hc_register"]["write"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            cache_idx, hc_value
        )
        if result is not None:
            print "Error: maybe wrong in update_hc_value"

    def read_hcf_state(self):
        if DEBUG_OPTION:
            print("Debug: reading hcf state in switch...")
        function_name = self.dp_intfc_func["hcf_state"]["read"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            0, self.dp_config["hw_sync_flag"]
        )
        return result[1]
        # Extracting info from the result is to be verified

    def switch_to_learning_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to learning...")
        function_name = self.dp_intfc_func["hcf_state"]["write"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"], 0, 0
        )
        if result is not None:
            print "Error: maybe wrong in switch_to_learning_state"
        # Extracting info from the result is to be verified

    def switch_to_filtering_state(self):
        if DEBUG_OPTION:
            print("Debug: switching hcf state to filtering...")
        function_name = self.dp_intfc_func["hcf_state"]["write"]
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"], 0, 1
        )
        if result is not None:
            print "Error: maybe wrong in switch_to_filtering_state"
        # Extracting info from the result is to be verified

    # Add entry into IP2HC Match-Action-Table
    def add_into_ip2hc_mat(self, ip_addr, cache_idx):
        # if type(ip_addr) != str:
            # ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        # # Temporary method...
        # ip_addr = ip_addr.replace('0', '10', 1)
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        if DEBUG_OPTION:
            print(
                "Debug: adding entry of %s into IP2HC-MAT with cache_idx %d ..."
                % (ip_addr, cache_idx)
            )
        function_name = self.dp_intfc_func["ip2hc_mat"]["add"]
        match_spec = eval(self.dp_intfc_spec["ip2hc_mat"]["match"])(ip_addr)
        action_spec = eval(self.dp_intfc_spec["ip2hc_mat"]["action"])(cache_idx)
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"],
            match_spec, action_spec
        )
        if DEBUG_OPTION:
            print("Debug: table add for IP2HC-MAT success")
            print("Debug: now %d entries exist in IP2HC-MAT" % result)
        return result
        # Extracting info(entry_handle) from the result is to be completed

    # Delete entry into IP2HC Match-Action-Table
    def delete_from_ip2hc_mat(self, ip_addr):
        # if type(ip_addr) != str:
            # ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        # # Temporary method...
        # ip_addr = ip_addr.replace('0', '10', 1)
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        if DEBUG_OPTION:
            print(
                "Debug: deleting IP2HC-MAT with ip %s ..." % ip_addr
            )
        function_name = self.dp_intfc_func["ip2hc_mat"]["delete"]
        match_spec = eval(self.dp_intfc_spec["ip2hc_mat"]["match"])(ip_addr)
        result = getattr(self.dp_intfc, function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev_tgt"], match_spec
        )
        if result is not None:
            print "Error: maybe wrong in delete_from_ip2hc_mat"
        # Extracting info from the result is to be verified

    def get_digest(self):
        # if DEBUG_OPTION:
        #     print("Debug: getting diget ...")
        function_name = self.dp_intfc_func["digest_fields"]["get"]
        result=getattr(self.dp_intfc,function_name)(self.dp_config["sess_hdl"])
        return result

    def register_digest(self):
        # if DEBUG_OPTION:
        #     print("Debug: getting diget ...")
        function_name = self.dp_intfc_func["digest_fields"]["register"]
        result=getattr(self.dp_intfc,function_name)(
            self.dp_config["sess_hdl"], self.dp_config["dev"]
        )
        if result is not None:
            print "Error: maybe wrong in register_digest"
        # Extracting info from the result is to be verified

    def notify_digest(self, msg_ptr):
        # if DEBUG_OPTION:
        #     print("Debug: getting diget ...")
        function_name = self.dp_intfc_func["digest_fields"]["notify"]
        result = getattr(self.dp_intfc,function_name)(
            self.dp_config["sess_hdl"], msg_ptr
        )
        if result is not None:
            print "Error: maybe wrong in notify_digest"
        # Extracting info from the result is to be verified

    def convert_to_unsigned(self, integer, width):
        return integer & ((1 << width) - 1)

class NetHCFSwitchBMv2:
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
            print "Error: Can't read miss counter!\n"
            print self.error_hint_str
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
            print "Error: Can't reset miss counter!\n"
            print self.error_hint_str

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
            print "Error: Can't read mismatch counter!\n"
            print self.error_hint_str
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
            print "Error: Can't reset mismatch counter!\n"
            print self.error_hint_str

    def read_hits_counter_cmd(self, cache_idx):
        return (
            '''echo "counter_read %s %d" | %s %s %d'''
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
            packets_str = result[result.index("packets="):].split(',')[0]
            match_times = int(packets_str.split('=')[1])
        except:
            print "Error: Can't read hits counter!\n"
            print self.error_hint_str
            return 0
        else:
            if DEBUG_OPTION:
                print("Debug: hits counter is %d" % match_times)
            return match_times

    def reset_hits_counter_cmd(self):
        return (
            '''echo "counter_reset %s" | %s %s %d'''
            % (self.ip2hc_counter,
               self.target_switch, self.target_code, self.target_port)
        )

    def reset_hits_counter(self):
        if DEBUG_OPTION:
            print("Debug: resetting hits counter...")
        result = os.popen(self.reset_hits_counter_cmd()).read()
        if "Done" not in result:
            print "Error: Can't reset hits counter!\n"
            print self.error_hint_str

    # Add entry into IP2HC Match-Action-Table
    def add_into_ip2hc_mat_cmd(self, ip_addr, cache_idx):
        if type(ip_addr) != str:
            ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        # Temporary method...
        ip_addr = ip_addr.replace('0', '10', 1)
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
            print "Error: Can't add entry into IP2HC Match Action Table!\n"
            print self.error_hint_str
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
            print "Error: Can't write into hc value register!\n"
            print self.error_hint_str

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
            print "Error: Can't delete entry from IP2HC MatchActionTable!\n"
            print self.error_hint_str

    # Get the entry index in IP2HC-MAT
    def index_ip2hc_mat_cmd(self, ip_addr, cache_idx):
        # if type(ip_addr) != str:
            # ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
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
            print "Error: Can't read register hcf_state!\n"
            print self.error_hint_str
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
            print "Error: Can't write register hcf_state!\n"
            print self.error_hint_str
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
            print "Error: Can't write register hcf_state!\n"
            print self.error_hint_str
            return -1

