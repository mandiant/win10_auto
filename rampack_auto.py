import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from flare_emu import flare_emu


class RamPack():
    def __init__(self):
        self.logger = logging.getLogger("RamPack") # TODO overwritten by child logs
        return

    def find_ida_name(self, fn_name):
        self.logger.info("searching for {0}...".format(fn_name))
        for name_addr in idautils.Names():
            if fn_name in name_addr[1]:
                self.logger.info("found {0} @ {1}".format(name_addr[1], hex(name_addr[0])))
                return name_addr
        self.logger.error("{0} NOT FOUND".format(fn_name))
        return None

    def get_cs(self):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        return cs

    def get_flare_emu(self):
        fe = flare_emu.EmuHelper()
        return fe

    def iter_fn(self, addr):
        cs = self.get_cs()
        for insn_addr in idautils.FuncItems(addr):
            for insn in cs.disasm(idc.GetManyBytes(insn_addr, idc.ItemSize(insn_addr)), insn_addr):
                yield insn

    def locate_call_in_fn(self, fn_start, fn_call):
        (addr_start, name_start) = self.find_ida_name(fn_start)
        (addr_end, name_end) = self.find_ida_name(fn_call)

        for insn in self.iter_fn(addr_start):
            if insn.id == capstone.x86.X86_INS_CALL:
                if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                    call_offset = insn.operands[0].imm
                    if call_offset == addr_end:
                        endAddr = insn.address
                        self.logger.info("located {0} in {1} @ {2}".format(name_end, name_start, hex(endAddr)))
                        return (addr_start, endAddr)
        self.logger.error("Failed to locate {0}".format(name_end))
        return (None, None)

    @staticmethod
    def patgen(buf_len):
        pat = ""
        for u in string.ascii_uppercase:
            for l in string.ascii_lowercase:
                for i in string.digits:
                    pat += "".join([u,l,i])
                    buf_len -= 3
                    if buf_len < 0:
                        return pat


    @staticmethod
    def eHookDbg(uc, address, size, user_data):
        fe = user_data['EmuHelper']
        dis = idc.GetDisasm(address)
        fe.logger.info("\n".join([dis, fe.getEmuState()]))
        return

    @staticmethod
    def eHookDerefMonitor(uc, address, size, user_data):
        # possible TODO
        return

    @staticmethod
    def eHookTrace(uc, address, size, user_data):
        user_storage = user_data['EmuHelper'].getUserStorage()
        if not user_storage.has_key('cs'):
            user_storage['cs'] = RamPack().get_cs()
            RamPack().logger.debug("created cs instance")
        if not user_storage.has_key('trace'):
            user_storage['trace'] = []

        ctx = uc.context_save()
        for insn in user_storage['cs'].disasm(idc.GetManyBytes(address, idc.ItemSize(address)), address):
            user_storage['trace'].append({'cs_insn':insn, 'uc_ctx':ctx})

        return

    @staticmethod
    def tHook(fe, address, argv, userData):
        RamPack().logger.debug("Hit target @ {0}".format(hex(address)))
        return


class Magic(RamPack):
    cs = None

    def __init__(self):
        self.logger = logging.getLogger("Magic")
        self.cs = self.get_cs()
        return

    # Requirements: PDB & IDA
    def smglobals_ida(self):
        for va, name in idautils.Names():
            if "?SmGlobals" in name:
                return va - idaapi.get_imagebase()
        return None

    # Requirements: PDB & IDA
    def mmpagefilearray_ida(self):
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn in self.iter_fn(self.cs, addr):
            if len(insn.operands) == 2:
                if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                    if insn.operands[1].mem.disp:
                        if insn.sib:
                            if insn.operands[1].mem.disp != 0:
                                self.logger.info("offset %x" % insn.operands[1].mem.disp)
                            if insn.sib_base != 0:
                                self.logger.info("sib_base: %s" % (insn.reg_name(insn.sib_base)))
                            if insn.sib_index != 0:
                                self.logger.info("sib_index: %s" % (insn.reg_name(insn.sib_index)))
                            if insn.sib_scale != 0:
                                self.logger.info("sib_scale: %d" % (insn.sib_scale))
                            
                            return insn.operands[1].mem.disp

        return None


class SmkmStoreMgr(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.fe = self.get_flare_emu()
        return

    def smkm_ida(self):
        return 0    # constant across win10
        
    def vlock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmFeReadInitiate", "ExAcquirePushLockSharedEx")

        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset 
        addr_smkmstoremgr = 0x1000
        regState = {'ecx':addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registerState=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr

    def key_to_storetree(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmFeCheckPresent", "BTreeSearchKey")

        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset 
        addr_smkmstoremgr = 0x1000
        regState = {'ecx':addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registerState=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr


class Smkm(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("SMKM")
        self.fe = self.get_flare_emu()
        return

    def store_metadata_array(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", addr_smkmstoremgr))
        num_store = 0x0
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registerState=regState)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr


class SmkmStoreMetadata(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("SMKM_STORE_METADATA")
        self.fe = self.get_flare_emu()
        return

    def sizeof(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0xFF
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registerState=regState)
        return self.fe.getRegVal('edx') + 1

    def maxstore(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registerState=regState)
        return self.fe.getRegVal('eax') + 1

    def smkm_store(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmIoCtxQueueWork", "SmWorkItemQueue")
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

        self.fe.iterate([endAddr], self.tHook, callHook=cHook, emuHook=eHook)
        user_storage = self.fe.getUserStorage()
        return user_storage['result']


class SmkmStore(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("SMKM_STORE")
        self.fe = self.get_flare_emu()
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
            target = {'type':None, 'value':None}
            if reverse:
                trace = trace[::-1]

            for t in trace:
                t = t['cs_insn']
                if not found_stack_write:
                    if t.reg_write(capstone.x86.X86_REG_ESP):  # if ESP modified
                        if stack_pos == current_stack_loc:
                            found_stack_write = True
                            self.logger.info("Found stack mod of interest @ {0}".format(hex(t.address)))
                            if len(t.operands) == 1: # works because i'm expecting a push right now
                                target['type'] = t.operands[0].type
                                target['value'] = t.operands[0].value
                        else:
                            current_stack_loc += 1
                else:
                    if len(t.operands) == 2:
                        if(t.operands[0].type == capstone.x86.X86_OP_REG):
                            if(t.operands[0].value.reg == target['value'].reg):
                                if t.operands[1].type == capstone.x86.X86_OP_MEM:
                                    self.logger.debug(idc.GetDisasm(t.address))
                                    found_deref = True

                if found_deref:
                    break

            return t.operands[1].value.mem.disp

        (startAddr, endAddr) = self.locate_call_in_fn("?SmPageRead", "SmIoCtxQueueWork")
        self.fe.iterate([endAddr], self.tHook, emuHook=self.eHookTrace)
        offset = stacktrack(self.fe.getUserStorage()['trace'], 0, reverse=True)

        return offset

    def bitfield(self):
        # searches for bMappingFlags and dword aligns to get bVal
        (startAddr, endAddr) = self.locate_call_in_fn("SmStStart", "SmKmStoreHelperInitialize")
        self.fe.iterate([endAddr], self.tHook, emuHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace'][::-1]:
            t = t['cs_insn']
            if t.mnemonic == "test":
                offset = t.operands[0].value.mem.disp & 0xfffffffc # dword align to get the start of the bitfield
                break
        return offset

    def vlock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStDirectReadIssue", "ExAcquirePushLockSharedEx")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.getRegVal('ecx')

    def leaf_page_id(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStAcquireStoreLockExclusive", "ExAcquirePushLockExclusiveEx")
        #start emulation at exacquirepushlock
        self.fe.emulateRange(endAddr, emuHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace']:
            if t['cs_insn'].mnemonic == "inc":
                offset = t['cs_insn'].operands[0].value.mem.disp
        return offset

    def max_region_ref_count(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStUnmapVirtualRegion", "SmAcquireReleaseCharges")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx':lp_smkmstore}
        self.fe.emulateRange(startAddr, registerState=regState, endAddr=endAddr)
        
        # This works because zero'd mem leads to a failure, which calls SmAcquireReleaseCharges
        # SmAcquireReleaseCharges appears to use the max_region_ref_count as its first arg
        reg_ecx = self.fe.getRegVal('ecx')
        return pat.find(struct.pack("<I", reg_ecx))

    def compressed_region_ptr_array(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStMapVirtualRegion")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx':lp_smkmstore}
        self.fe.emulateRange(fn_addr, registerState=regState, emuHook=self.eHookTrace)

        # isolates the call block I'm interested in
        t_filtered = []
        for t in self.fe.getUserStorage()['trace']:
            t_filtered.append(t)
            if capstone.x86.X86_GRP_JUMP in t['cs_insn'].groups:
                endAddr = t['cs_insn'].address
                self.logger.debug("jump class @ {}".format(hex(endAddr)))
                break

        self.fe.mu.context_restore(t_filtered[-1]['uc_ctx'])
        reg_esi = self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ESI)
        return pat.find(struct.pack("<I", reg_esi))


    def sm_virtual_region(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStCheckLockInProgressRegionComplete")
        lp_smkmstore = self.fe.loadBytes("\xff"*0x1000*2)
        regState = {'ecx':lp_smkmstore, 'edx':0xffffffff}
        def cHook(uc, address, size, user_data):
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0xC0000120)

        self.fe.emulateRange(fn_addr, registerState=regState, callHook=cHook)
        smkmstore_bytes = self.fe.getEmuBytes(lp_smkmstore, 0x1000*2)
        return smkmstore_bytes.find("\x00"*4)
        
    def store_owner_process(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStDirectRead", "KiStackAttachProcess")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)

        def pHook(self, mu, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            fe = userData['EmuHelper']
            user_storage = fe.getUserStorage()
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_smkmstore)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        return pat.find(struct.pack("<I", reg_ecx))

    def lock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStAcquireStoreLockExclusive", "ExAcquirePushLockExclusiveEx")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ECX)


class StStore(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("ST_STORE")
        self.fe = self.get_flare_emu()
        return

    def sizeof(self):
        return

    def st_data_mgr(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StStart", "StDmStart")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_EDX)


class StDataMgr(RamPack):
    def __init__(self):
        self.logger = logging.getLogger("ST_STORE")
        self.fe = self.get_flare_emu()
        return

    def sizeof(self):
        return

    def pages_tree(self):
        # appears to always be first entry
        return 0

    def chunk_metadata(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StDmpSinglePageAdd", "SmHpChunkAlloc")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ECX)

    def store_flags(self):
        (fn_addr, fn_name) = self.find_ida_name("?StDmIsCurrentRegion")
        self.fe.emulateRange(fn_addr, emuHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace']:
            t = t['cs_insn']
            if t.mnemonic == "cmp":
                offset = t.operands[0].value.mem.disp
                break
        return offset

    def smkm_store(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StReleaseRegion", "?SmStReleaseVirtualRegion")
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, mu, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            fe = userData['EmuHelper']
            user_storage = fe.getUserStorage()
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        return pat.find(struct.pack("<I", reg_ecx))

    def region_size_mask(self):
        (startAddr, fn_name) = self.find_ida_name("?StDmpSinglePageRetrieve")
        (endAddr, fn_name) = self.find_ida_name("?SmStMapVirtualRegion")
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, mu, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            fe = userData['EmuHelper']
            user_storage = fe.getUserStorage()
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)

        def fn_path(origin, destination, fpath=[]):
            for x in XrefsTo(destination):
                x_fn = get_func_attr(x.frm, FUNCATTR_START)
                if x_fn == origin:
                    fpath.append(x_fn)
                    return fpath
            
            for x in XrefsTo(destination):
                x_fn = get_func_attr(x.frm, FUNCATTR_START)
                fpath.append(x_fn)
                return check_xrefs(origin, x_fn, fpath)

        for fn in fn_path(startAddr, endAddr):
            (startAddr, endAddr) = self.locate_call_in_fn("?StReleaseRegion", "?SmStReleaseVirtualRegion")


        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook, emuHook=self.eHookDbg)
        reg_esp = self.fe.mu.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        pat_shl4 = self.fe.getEmuBytes(reg_esp, 0x4)
        return pat, pat_shl4

    def region_lsb(self):
        return

    def data_offset_in_compressed_buf(self):
        return

    def compression_format_and_engine(self):
        return

    def smcr_integrity(self):
        return

    def region_written_size_array(self):
        return
        

class DumpConfig():
    def __init__(self):
        return

def main():
    mgc = Magic()
    smglobals = mgc.smglobals_ida()
    pagefilearray = mgc.mmpagefilearray_ida()
    logging.info("nt!SmGlobals: {0:x}".format(smglobals))
    logging.info("nt!MmPagingFile: {0:x}".format(pagefilearray))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
