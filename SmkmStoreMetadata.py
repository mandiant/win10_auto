import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from flare_emu import flare_emu

from RamPack import RamPack


class SmkmStoreMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("SMKM_STORE_METADATA.Size: 0x{0:x}".format(self.sizeof()))
        self.logger.info("SMKM_STORE_METADATA.pSmkmStore: 0x{0:x}".format(self.smkm_store()))

    def sizeof(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('eax') + 1

    def maxstore(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        num_store = 0xFF
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('edx') + 1

    def smkm_store(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmIoCtxQueueWork", ["SmWorkItemQueue", "SmStWorkItemQueue"])
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.getRegVal('ecx')

    def rundown_ref_1(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmKmStoreReference", "ExAcquireRundownProtection")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.getRegVal('ecx')

    def flags(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmKmStoreReferenceEx", "SmKmStoreReference")
        (startAddr, addr_trigger) = self.locate_call_in_fn("SmKmStoreReferenceEx", "SmKmStoreRefFromStoreIndex")

        # this works because SmKmStoreReferenceEx is a thin wrapper, with only one mem deref
        def eHook(uc, address, size, user_data):
            user_storage = user_data['EmuHelper'].getUserStorage()
            if user_storage.has_key('g_deref_monitor_active'):
                if not user_storage.has_key('cs'):
                    user_storage['cs'] = self.get_cs()
                    self.logger.debug("created cs instance")
                for insn in user_storage['cs'].disasm(idc.GetManyBytes(address, idc.ItemSize(address)), address):
                    if len(insn.operands) == 2:
                        if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                            if insn.operands[1].mem.disp:
                                self.logger.debug("struc offset: {0}".format(hex(insn.operands[1].mem.disp)))
                                user_storage['result'] = insn.operands[1].mem.disp

            return

        def cHook(uc, address, size, user_data):
            if address == addr_trigger:
                user_storage = user_data['EmuHelper'].getUserStorage()
                self.logger.debug("enabled deref monitor")
                user_storage['g_deref_monitor_active'] = True
            return

        self.fe.iterate([endAddr], self.tHook, callHook=cHook, instructionHook=eHook)
        user_storage = self.fe.getUserStorage()
        return user_storage['result']
