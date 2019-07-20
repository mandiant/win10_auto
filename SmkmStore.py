import logging
import struct

import unicorn

from RamPack import RamPack


class SmkmStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump32(self):
        self.logger.info("SMKM_STORE.StStore: 0x{0:x}".format(self.Info.arch_fns['x86']['sks32_ststore'](self)))
        self.logger.info("SMKM_STORE.pCompressedRegionPtrArray: 0x{0:x}".format(self.Info.arch_fns['x86']['sks32_compressedregionptrarray'](self)))
        self.logger.info("SMKM_STORE.StoreOwnerProcess: 0x{0:x}".format(self.Info.arch_fns['x86']['sks32_storeownerprocess'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    def sks32_ststore(self):
        # Assumption is that the ST_STORE struct is nested @ offset 0
        return 0

    @RamPack.Info.arch32
    def sks32_compressedregionptrarray(self):
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

    @RamPack.Info.arch32
    def sks32_storeownerprocess(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmStDirectRead@?$SMKM_STORE", "KiStackAttachProcess")
        pat = self.patgen(8192)
        lp_smkmstore = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData["EmuHelper"].uc.reg_write(unicorn.x86_const.UC_X86_REG_ECX, lp_smkmstore)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        reg_ecx = self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        return pat.find(struct.pack("<I", reg_ecx))
