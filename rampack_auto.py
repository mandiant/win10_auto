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
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("RamPack") # TODO overwritten by child logs
        self.logger.setLevel(loglevel)
        return

    def find_ida_name(self, fn_name):
        self.logger.debug("Searching for {0}...".format(fn_name))
        for name_addr in idautils.Names():
            if fn_name in name_addr[1]:
                self.logger.debug("found {0} @ {1}".format(name_addr[1], hex(name_addr[0])))
                return name_addr
        self.logger.error("{0} NOT FOUND".format(fn_name))

    def get_cs(self):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        return cs

    def get_flare_emu(self, loglevel=logging.INFO):
        fe = flare_emu.EmuHelper(loglevel=loglevel)
        return fe

    def iter_fn(self, addr):
        cs = self.get_cs()
        for insn_addr in idautils.FuncItems(addr):
            for insn in cs.disasm(idc.GetManyBytes(insn_addr, idc.ItemSize(insn_addr)), insn_addr):
                yield insn

    def locate_call_in_fn(self, fns_start, fns_call):
        if type(fns_start) is not list:
            fns_start = [fns_start]
        if type(fns_call) is not list:
            fns_call = [fns_call]

        for fn_start in fns_start:
            for fn_call in fns_call:
                (addr_start, name_start) = self.find_ida_name(fn_start)
                (addr_end, name_end) = self.find_ida_name(fn_call)

                for insn in self.iter_fn(addr_start):
                    if insn.id == capstone.x86.X86_INS_CALL:
                        if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                            call_offset = insn.operands[0].imm
                            if call_offset == addr_end:
                                addr_end = insn.address
                                self.logger.debug("located {0} in {1} @ 0x{2:x}".format(name_end, name_start, addr_end))
                                return (addr_start, addr_end)
                self.logger.error("Failed to locate {0} within {1}".format(name_end, name_start))

        self.logger.error("locate_call_in_fn failed")
        return (None, None)

    @staticmethod
    def patgen(buf_len, size=4):
        pat = ""
        symbols = "`~!@#$%^&*()-=_+[]\{}|;':,./<>?"
        if size == 4:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        for s in symbols:
                            pat += "".join([u,l,i,s])
                            buf_len -= 3
                            if buf_len < 0:
                                return pat
        elif size == 3:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        pat += "".join([u,l,i])
                        buf_len -= 3
                        if buf_len < 0:
                            return pat

        elif size == 2:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                        pat += "".join([u,l])
                        buf_len -= 3
                        if buf_len < 0:
                            return pat
                        
        else:
            self.logger.error("Unsupported size fed to pattern generator")


    """
    Use with instructionHook callback to get a disassembly + reg dump
    """
    def eHookDbg(self, uc, address, size, user_data):
        fe = user_data['EmuHelper']
        dis = idc.GetDisasm(address)
        fe.logger.info("\n".join([dis, fe.getEmuState()]))
        return

    def eHookDerefMonitor(self, uc, address, size, user_data):
        # possible TODO
        return


    def eHookTrace(self, uc, address, size, user_data):
        if not user_data.has_key('cs'):
            user_data['cs'] = RamPack().get_cs()
            RamPack().logger.debug("created cs instance")
        if not user_data.has_key('trace'):
            user_data['trace'] = []

        ctx = uc.context_save()
        for insn in user_data['cs'].disasm(idc.GetManyBytes(address, idc.ItemSize(address)), address):
            mem_regions = [reg_start for (reg_start, reg_end, reg_perms) in uc.mem_regions()]
            user_data['trace'].append({'cs_insn':insn, 'uc_ctx':ctx, 'mem_regions':tuple(mem_regions)})

        # self.fe_userdata['trace'] = copy.deepcopy(user_data['trace']) IDA falls over
        self.fe_userdata = user_data # TODO - Objects in dictionary may not be accurate due to linking
        return

    def tHook(self, fe, address, argv, userData):
        RamPack().logger.debug("Hit target @ {0}".format(hex(address)))
        return


class Magic(RamPack):
    cs = None

    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("Magic")
        self.logger.setLevel(loglevel)
        self.cs = self.get_cs()
        return

    def _dump(self):
        smglobals = self.smglobals_ida()
        pagefilearray = self.mmpagefilearray_ida()
        self.logger.info("MAGIC.SmGlobals: 0x{0:x}".format(smglobals))
        self.logger.info("MAGIC.MmPagingFile: 0x{0:x}".format(pagefilearray))

    # Requirements: PDB & IDA
    def smglobals_ida(self):
        for va, name in idautils.Names():
            if "?SmGlobals" in name:
                return va - idaapi.get_imagebase()
        self.logger.error("SmGlobals could not be resolved.")
        return None

    # Requirements: PDB & IDA
    def mmpagefilearray_ida(self):
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn in self.iter_fn(addr):
            if len(insn.operands) == 2:
                if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                    if insn.operands[1].mem.disp:
                        if insn.sib:
                            if insn.operands[1].mem.disp != 0:
                                self.logger.debug("offset %x" % insn.operands[1].mem.disp)
                            if insn.sib_base != 0:
                                self.logger.debug("sib_base: %s" % (insn.reg_name(insn.sib_base)))
                            if insn.sib_index != 0:
                                self.logger.debug("sib_index: %s" % (insn.reg_name(insn.sib_index)))
                            if insn.sib_scale != 0:
                                self.logger.debug("sib_scale: %d" % (insn.sib_scale))
                            
                            return insn.operands[1].mem.disp
        self.logger.error("MmPagingFile could not be resolved.")
        return None


class SmkmStoreMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("SMKM_STORE_MGR.Smkm: 0x{0:x}".format(self.smkm()))
        self.logger.info("SMKM_STORE_MGR.BTreeGlobalStore: 0x{0:x}".format(self.key_to_storetree()))

    def smkm(self):
        return 0    # constant across win10
        
    def vlock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmFeReadInitiate", "ExAcquirePushLockSharedEx")

        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset 
        addr_smkmstoremgr = 0x1000
        regState = {'ecx':addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr

    def key_to_storetree(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmFeCheckPresent", "?BTreeSearchKey@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY")
        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset 
        addr_smkmstoremgr = 0x1000
        regState = {'ecx':addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr


class Smkm(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        metadata_array = self.store_metadata_array()
        self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(metadata_array))

    def store_metadata_array(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", addr_smkmstoremgr))
        num_store = 0x0
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr


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
        num_store = 0xFF
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('edx') + 1

    def maxstore(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('eax') + 1

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
        self.fe.emulateRange(endAddr, instructionHook=self.eHookTrace)
        for t in self.fe.getUserStorage()['trace']:
            if t['cs_insn'].mnemonic == "inc":
                offset = t['cs_insn'].operands[0].value.mem.disp
        return offset

    def max_region_ref_count(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmStUnmapVirtualRegion", "SmAcquireReleaseCharges")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx':lp_smkmstore}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)
        
        # This works because zero'd mem leads to a failure, which calls SmAcquireReleaseCharges
        # SmAcquireReleaseCharges appears to use the max_region_ref_count as its first arg
        reg_ecx = self.fe.getRegVal('ecx')
        return pat.find(struct.pack("<I", reg_ecx))

    def compressed_region_ptr_array(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStMapVirtualRegion")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        regState = {'ecx':lp_smkmstore}

        mHookOutput = {'pattern':None}
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
        lp_smkmstore = self.fe.loadBytes("\xff"*0x1000*2)
        regState = {'ecx':lp_smkmstore, 'edx':0xffffffff}
        def cHook(uc, address, size, user_data):
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0xC0000120)

        self.fe.emulateRange(fn_addr, registers=regState, callHook=cHook)
        smkmstore_bytes = self.fe.getEmuBytes(lp_smkmstore, 0x1000*2)
        return smkmstore_bytes.find("\x00"*4)
        
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


class StStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("ST_STORE.StDataMgr: 0x{0:x}".format(self.st_data_mgr()))
        return

    def sizeof(self):
        return

    def st_data_mgr(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StStart", "StDmStart")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX)


class StDataMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("ST_DATA_MGR.sLocalTree: 0x{0:x}".format(self.pages_tree()))
        self.logger.info("ST_DATA_MGR.ChunkMetadata: 0x{0:x}".format(self.chunk_metadata()))
        self.logger.info("ST_DATA_MGR.SmkmStore: 0x{0:x}".format(self.smkm_store()))
        self.logger.info("ST_DATA_MGR.RegionSizeMask: 0x{0:x}".format(self.region_size_mask()))
        self.logger.info("ST_DATA_MGR.RegionLSB: 0x{0:x}".format(self.region_lsb()))
        self.logger.info("ST_DATA_MGR.CompressionAlg: 0x{0:x}".format(self.compression_format_and_engine()))
        return

    def sizeof(self):
        return

    def pages_tree(self):
        # appears to always be first entry
        return 0

    def chunk_metadata(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StDmpSinglePageAdd", "SmHpChunkAlloc")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)

    def store_flags(self):
        (fn_addr, fn_name) = self.find_ida_name("?StDmIsCurrentRegion")
        self.fe.emulateRange(fn_addr, instructionHook=self.eHookTrace)
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

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        return pat.find(struct.pack("<I", reg_ecx))

    """
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+47   024 mov     eax, [ebx+ST_DATA_MGR.dwRegionMask]
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+4D   024 lea     edx, [ebx+20Ch]
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+53   024 push    ecx
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+54   028 inc     eax
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+55   028 push    eax
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+56   02C push    ecx
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+57   030 push    edi
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+58   034 mov     ecx, ebx
    ST_STORE<SM_TRAITS>::StDmRegionRemove(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ulong *)+5A   034 call    ?StDmRegionEvict@?$ST_STORE@USM_TRAITS@@@@SGJPAU_ST_DATA_MGR@1@PAU_STDM_SEARCH_RESULTS@1@KKKK@Z ; ST_STORE<SM_TRAITS>::StDmRegionEvict(ST_STORE<SM_TRAITS>::_ST_DATA_MGR *,ST_STORE<SM_TRAITS>::_STDM_SEARCH_RESULTS *,ulong,ulong,ulong,ulong)
    """
    def region_size_mask(self):
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)
        
        (startAddr, endAddr) = self.locate_call_in_fn("?StDmRegionRemove", "?StDmRegionEvict")


        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_esp = self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        stack_bytes = self.fe.getEmuBytes(reg_esp, 0xC)
        third_arg = stack_bytes[0x8:]
        return pat.find(struct.pack("<I", struct.unpack("<I", third_arg)[0] - 1))

    def region_lsb(self):
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)
        region_lsb_pattern = {'pattern':0}

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)

        # Using an instruction hook because data in offset is difficult to track beyond arithmetic ops like shr
        def iHook(uc, address, size, user_data):
            dis = idc.GetDisasm(address)
            if "shr" in dis:
                # This is the "equivalent" of using nonlocal in py3
                region_lsb_pattern['pattern'] += user_data['EmuHelper'].uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDeviceWorkItemCleanup", "?StRegionReadDereference")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook, instructionHook=iHook)
        return pat.find(struct.pack("<I", region_lsb_pattern["pattern"]))

    def data_offset_in_compressed_buf(self):
        return 0

    def compression_format_and_engine(self):
        pat = self.patgen(1024, size=2)  # Reduced pattern len & size to detect WORD
        lp_stdatamgr = self.fe.loadBytes(pat)
        region_lsb_pattern = {'pattern':0}

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_stdatamgr)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDmSinglePageCopy", "_RtlDecompressBufferEx@")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_esp = self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        stack_bytes = self.fe.getEmuBytes(reg_esp, 0x2) # Using 0x2 because this is a WORD field
        return pat.find(stack_bytes)

    def smcr_integrity(self):
        return

    def region_written_size_array(self):
        return
        
"""
'_ST_CHUNK_METADATA': [None, {
    'ChunkPtrArray': [0x0, ['array', 32, ['pointer', ['void']]]],
    'BitValue': [0x108, ['unsigned int']],
    'PageRecordsPerChunkMask': [0x10C, ['unsigned int']],
    'PageRecordSize': [0x110, ['unsigned int']],
    'ChunkPageHeaderSize': [0x118, ['unsigned int']],
}],
"""
class StChunkMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_CHUNK_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump():
        return

    def chunk_ptr_array(self):
        return

    def bit_value(self):
        return

    def page_records_per_chunk_mask(self):
        return

    def page_record_size(self):
        return

    def chunk_page_header_size(self):
        return

def main():
    Magic()._dump()
    SmkmStoreMgr()._dump()
    Smkm()._dump()
    SmkmStoreMetadata()._dump()
    SmkmStore()._dump()
    StStore()._dump()
    StDataMgr()._dump()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
