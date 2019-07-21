"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: SmkmStore.py
Description: The SmkmStore class corresponds to the Windows 10 SMKM_STORE structure.
Each SMKM_STORE structure represents a single store. The information in this
structure, and nested structures, is used to locate the specific region containing the
compressed page.
"""
import logging
import struct

from RamPack import RamPack


class SmkmStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM_STORE.StStore: {0:#x}".format(self.Info.arch_fns[arch]['sks_ststore'](self)))
        self.logger.info("SMKM_STORE.pCompressedRegionPtrArray: {0:#x}".format(self.Info.arch_fns[arch]['sks_compressedregionptrarray'](self)))
        self.logger.info("SMKM_STORE.StoreOwnerProcess: {0:#x}".format(self.Info.arch_fns[arch]['sks_storeownerprocess'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sks_ststore(self):
        # Assumption is that the ST_STORE struct is nested @ offset 0
        return 0

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sks_compressedregionptrarray(self):
        (fn_addr, fn_name) = self.find_ida_name("SmStMapVirtualRegion")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        mHookData = {'offset': None, 'structAddr': lp_smkmstore}

        def mHook(uc, accessType, memAccessAddress, memAccessSize, memValue, userData):
            if mHookData['offset']:
                return

            if accessType == 16: # UC_MEM_READ
                self.logger.debug("Mem read @ 0x{0:x}: {1}".format(memAccessAddress, memValue))
                mHookData['offset'] = memAccessAddress
            elif accessType == 17: # UC_MEM_WRITE
                self.logger.debug("Mem write @ 0x{0:x}".format(memAccessAddress))
            elif accessType == 18: # UC_MEM_FETCH
                self.logger.debug("Mem fetch @ 0x{0:x}".format(memAccessAddress))
            else:
                self.logger.error("Mem unknown accessType @ 0x{0:x}".format(memAccessAddress))

        regState = {reg_cx: lp_smkmstore}
        self.fe.emulateRange(fn_addr, registers=regState, memAccessHook=mHook)
        return mHookData['offset'] - mHookData['structAddr']

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sks_storeownerprocess(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmStDirectRead@?$SMKM_STORE", "KiStackAttachProcess")
        pat = self.patgen(8192)
        addr_smkmstore = self.fe.loadBytes(pat)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        struct_fmt = "<Q" if self.Info.is_64bit() else "<I"

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData["EmuHelper"].uc.reg_write(userData["EmuHelper"].regs["cx"], addr_smkmstore)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.getRegVal(reg_cx)
        return pat.find(struct.pack(struct_fmt, reg_ecx))
