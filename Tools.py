"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar
Name: Tools.py

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
import string

import idc
import idautils
import idaapi

from flare_emu import flare_emu


class Tools():
    """
    The Tools class contains helper functions and is designed to be
    inherited by classes which perform the analysis of the Windows 10 kernel.
    """
    class Info():
        """
        The Info class contains architecture related information. It was originally
        designed as a separate class to support decorators which could be applied
        to class functions, signifying their architecture and usage. For example,
        a @volatility or @windriver decorator could be created for fields of interest
        to those specific products (as they differ).
        """
        arch_fns = {'x86': {}, 'x64': {}}

        @classmethod
        def arch32(self, fn):
            """
            Decorator signifying that a class function is meant for 32-bit binary analysis.
            """
            self.arch_fns['x86'][fn.__name__] = fn
            return fn

        @classmethod
        def arch64(self, fn):
            """
            Decorator signifying that a class function is meant for 64-bit binary analysis.
            """
            self.arch_fns['x64'][fn.__name__] = fn
            return fn

        @staticmethod
        def is_64bit():
            """
            Determine IDB binary architecture. is_32bit() always returns True, whereas is_64bit()
            returns False on 32-bit binaries.
            """
            info = idaapi.get_inf_structure()
            return info.is_64bit()

    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("TOOLS")
        self.logger.setLevel(loglevel)
        self.info = self.Info()
        return

    def find_ida_name(self, fn_name):
        """
        This functions serves as a soft search for function names. It exists to allow some flexibility
        when searching for mangled function names.
        """
        self.logger.debug("Searching for {0}...".format(fn_name))
        for name_addr in idautils.Names():
            if fn_name in name_addr[1]:
                self.logger.debug("found {0} @ {1}".format(name_addr[1], hex(name_addr[0])))
                return name_addr #Tuple
        self.logger.debug("{0} not found".format(fn_name))
        return None, None

    def get_flare_emu(self, loglevel=logging.INFO):
        """
        Retrieve the current EmuHelper instance.
        """
        fe = flare_emu.EmuHelper(loglevel=loglevel)
        return fe

    def iter_fn(self, startAddr):
        """
        Generator function designed to walk all instructions within a function, parse and yield them.
        """
        endAddr = idc.GetFunctionAttr(startAddr, idc.FUNCATTR_END)
        for head in idautils.Heads(startAddr, endAddr):
            yield head, idc.GetDisasm(head).split()[0], idc.GetOpnd(head, 0), idc.GetOpnd(head, 1)

    def locate_call_in_fn(self, fns_start, fns_call):
        """
        Designed to support FLARE-EMU's iternate function, it is primarily used to locate a stopping
        point within a function at which to terminate emulation. This is typically used to analyze
        arguments to the target function. The function supports list input as a way to maintain
        some flexibility between 32-bit and 64-bit binaries in which function names may change.
        """
        if type(fns_start) is not list:
            fns_start = [fns_start]
        if type(fns_call) is not list:
            fns_call = [fns_call]

        for fn_start in fns_start:
            (addr_start, name_start) = self.find_ida_name(fn_start)
            if addr_start is None or name_start is None:
                continue
            for fn_call in fns_call:
                (addr_end, name_end) = self.find_ida_name(fn_call)

                for insn_addr, insn, op0, op1 in self.iter_fn(addr_start):
                    if insn == "call":
                        if op0 == name_end:
                            self.logger.debug("located {0} in {1} @ {2:#x}".format(name_end, name_start, addr_end))
                            return addr_start, insn_addr

                self.logger.debug("Failed to locate {0} within {1}".format(name_end, name_start))

        self.logger.error("locate_call_in_fn failed")
        return None, None

    @staticmethod
    def patgen(buf_len, size=4):
        """
        The pattern generator is used to populate structures which are passed into functions
        as arguments. By monitoring outputs at certain points in the function, the sub-pattern can
        be searched for within the original pattern, helping us derive the offset from which it
        originated.
        """
        pat = ""

        symbols = "`~!@#$%^&*()-=_+[]\{}|;':,./<>?"
        if size == 4:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        for s in symbols:
                            pat += "".join([u, l, i, s])
                            buf_len -= size
                            if buf_len < 0:
                                return pat[:buf_len]
        elif size == 3:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        pat += "".join([u, l, i])
                        buf_len -= size
                        if buf_len < 0:
                            return pat[:buf_len]

        elif size == 2:
            for u in string.ascii_uppercase + symbols:
                for l in string.ascii_lowercase:
                    pat += "".join([u, l])
                    buf_len -= size
                    if buf_len < 0:
                        return pat[:buf_len]

    def eHookDbg(self, uc, address, size, user_data):
        """
        The function eHookDbg is a callback function used by iterate and emulateRange. The
        callback disassembles the instruction & prints registers. Designed for use with the
        instructionHook argument, it functions as a lightweight trace.
        """
        fe = user_data['EmuHelper']
        dis = idc.GetDisasm(address)
        fe.logger.info("\n".join([dis, fe.getEmuState()]))
        return

    def tHook(self, fe, address, argv, userData):
        """
        Used with FLARE-EMU's iterate to notify developer that iterate successfully hit the target.
        """
        Tools().logger.debug("Hit target @ {0}".format(hex(address)))
        return