import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from RamPack import RamPack


class SmkmStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("SMKM_STORE.StStore: 0x{0:x}".format(self.st_store()))
        self.logger.info("SMKM_STORE.pCompressedRegionPtrArray: 0x{0:x}".format(self.compressed_region_ptr_array()))
        self.logger.info("SMKM_STORE.StoreOwnerProcess: 0x{0:x}".format(self.store_owner_process()))
        return

    def sizeof(self):
        return

    def st_store(self):
        # Assumption is that the ST_STORE struct is nested @ offset 0
        return 0

    def store_index(self):
        # stop at a call, and figure out where the arg originated
        # trace is a series of csinsn objects that unicorn saved along the way
        # stack_pos is the arg you're interested in ex: 0, 1, 2...
        # prob nice to have reg context, but would need to have marker values to track- currently lots of zeroing
        # really should be reimplemented with support for a unicorn context to accompany the capstone
        # capstone regs_read, and regs_write doesn't work in my build, possibly 'next' branch
        def stacktrack(trace, stack_pos, reverse=False):
            current_stack_loc = 0
            found_stack_write = False
            found_deref = False
            target = {'type': None, 'value': None}
            if reverse:
                trace = trace[::-1]

            for t in trace:
                t = t['cs_insn']
                if not found_stack_write:
                    if t.reg_write(capstone.x86.X86_REG_ESP):  # if ESP modified
                        if stack_pos == current_stack_loc:
                            found_stack_write = True
                            self.logger.info("Found stack mod of interest @ {0}".format(hex(t.address)))
                            if len(t.operands) == 1:  # works because i'm expecting a push right now
                                target['type'] = t.operands[0].type
                                target['value'] = t.operands[0].value
                        else:
                            current_stack_loc += 1
                else:
                    if len(t.operands) == 2:
                        if (t.operands[0].type == capstone.x86.X86_OP_REG):
                            if (t.operands[0].value.reg == target['value'].reg):
                                if t.operands[1].type == capstone.x86.X86_OP_MEM:
                                    self.logger.debug(idc.GetDisasm(t.address))
                                    found_deref = True

                if found_deref:
                    break

            return t.operands[1].value.mem.disp

        (startAddr, endAddr) = self.locate_call_in_fn("?SmPageRead", "SmIoCtxQueueWork")
        self.fe.iterate([endAddr], self.tHook, instructionHook=self.eHookTrace)
        offset = stacktrack(self.fe.getUserStorage()['trace'], 0, reverse=True)

        return offset

    def bitfield(self):
        # searches for bMappingFlags and dword aligns to get bVal
        (startAddr, endAddr) = self.locate_call_in_fn("SmStStart", "SmKmStoreHelperInitialize")
        self.fe.iterate([endAddr], self.tHook, instructionHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace'][::-1]:
            t = t['cs_insn']
            if t.mnemonic == "test":
                offset = t.operands[0].value.mem.disp & 0xfffffffc  # dword align to get the start of the bitfield
                break
        return offset

    def vlock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStDirectReadIssue", "ExAcquirePushLockSharedEx")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.getRegVal('ecx')

    def leaf_page_id(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStAcquireStoreLockExclusive", "ExAcquirePushLockExclusiveEx")
        # start emulation at exacquirepushlock
        self.fe.emulateRange(endAddr, instructionHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace']:
            if t['cs_insn'].mnemonic == "inc":
                offset = t['cs_insn'].operands[0].value.mem.disp
        return offset

    def max_region_ref_count(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStUnmapVirtualRegion", "SmAcquireReleaseCharges")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx': lp_smkmstore}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)

        # This works because zero'd mem leads to a failure, which calls SmAcquireReleaseCharges
        # SmAcquireReleaseCharges appears to use the max_region_ref_count as its first arg
        reg_ecx = self.fe.getRegVal('ecx')
        return pat.find(struct.pack("<I", reg_ecx))

    def compressed_region_ptr_array(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStMapVirtualRegion")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx': lp_smkmstore}

        mHookOutput = {'pattern': None}

        def mHook(uc, accessType, memAccessAddress, memAccessSize, memValue, userData):
            if mHookOutput['pattern']:
                return

            if accessType == unicorn.unicorn_const.UC_MEM_READ:
                self.logger.debug("Mem read @ 0x{0:x}: {1}".format(memAccessAddress, memValue))
                read_bytes = userData["EmuHelper"].getEmuBytes(memAccessAddress, memAccessSize)
                mHookOutput['pattern'] = read_bytes
            elif accessType == unicorn.unicorn_const.UC_MEM_WRITE:
                self.logger.debug("Mem write @ 0x{0:x}".format(memAccessAddress))
            elif accessType == unicorn.unicorn_const.UC_MEM_FETCH:
                self.logger.debug("Mem fetch @ 0x{0:x}".format(memAccessAddress))
            else:
                self.logger.error("Mem unknown accessType @ 0x{0:x}".format(memAccessAddress))

        mu = self.fe.emulateRange(fn_addr, registers=regState, instructionHook=self.eHookTrace, memAccessHook=mHook)

        return pat.find(mHookOutput['pattern'])

    def sm_virtual_region(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStCheckLockInProgressRegionComplete")
        lp_smkmstore = self.fe.loadBytes("\xff" * 0x1000 * 2)
        regState = {'ecx': lp_smkmstore, 'edx': 0xffffffff}

        def cHook(uc, address, size, user_data):
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0xC0000120)

        self.fe.emulateRange(fn_addr, registers=regState, callHook=cHook)
        smkmstore_bytes = self.fe.getEmuBytes(lp_smkmstore, 0x1000 * 2)
        return smkmstore_bytes.find("\x00" * 4)

    def store_owner_process(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmStDirectRead@?$SMKM_STORE", "KiStackAttachProcess")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData["EmuHelper"].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_smkmstore)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        return pat.find(struct.pack("<I", reg_ecx))

    def lock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStAcquireStoreLockExclusive", "ExAcquirePushLockExclusiveEx")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
