import logging
import struct

import idc

from RamPack import RamPack

class StDataMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("ST_DATA_MGR.sLocalTree: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_localtree'](self)))
        self.logger.info("ST_DATA_MGR.ChunkMetadata: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_chunkmetadata'](self)))
        self.logger.info("ST_DATA_MGR.SmkmStore: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_smkmstore'](self)))
        self.logger.info("ST_DATA_MGR.RegionSizeMask: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_regionsizemask'](self)))
        self.logger.info("ST_DATA_MGR.RegionLSB: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_regionlsb'](self)))
        self.logger.info("ST_DATA_MGR.CompressionFormat: 0x{0:x}".format(self.Info.arch_fns[arch]['stdm_compressionformat'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_localtree(self):
        # appears to always be first entry
        return 0

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_chunkmetadata(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StDmpSinglePageAdd", "SmHpChunkAlloc")
        self.fe.iterate([endAddr], self.tHook)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        return self.fe.getRegVal(reg_cx)

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_smkmstore(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StReleaseRegion", "?SmStReleaseVirtualRegion")
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        struct_fmt = "<Q" if self.Info.is_64bit() else "<I"

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        return pat.find(struct.pack(struct_fmt, self.fe.getRegVal(reg_cx)))

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_regionsizemask(self):
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDmRegionRemove", "?StDmRegionEvict")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        if self.Info.is_64bit():
            reg_rsp = self.fe.getRegVal("rsp")
            stack_bytes = self.fe.getEmuBytes(reg_rsp, 0x28)
            third_arg = struct.unpack("<Q", stack_bytes[0x20:])[0]
        else:
            third_arg = self.fe.getArgv()[2]
        return pat.find(struct.pack("<I", third_arg - 1))  # Must be "<I" due to retrieval of a DWORD

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_regionlsb(self):
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)
        iHookData = {'pattern': None}

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        # Using an instruction hook because data in offset is difficult to track beyond arithmetic ops like shr
        def iHook(uc, address, size, userData):
            dis = idc.GetDisasm(address)
            if "shr" in dis[:3]:
                iHookData['pattern'] = struct.pack("<I", userData['EmuHelper'].uc.reg_read(userData["EmuHelper"].regs["cx"]))

        (startAddr, endAddr) = self.locate_call_in_fn("?StDeviceWorkItemCleanup", "?StRegionReadDereference")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook, instructionHook=iHook)
        return pat.find(iHookData["pattern"])

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def stdm_compressionformat(self):
        pat = self.patgen(2048, size=2)  # Reduced pattern len & size to detect WORD
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDmSinglePageCopy", ["_RtlDecompressBufferEx@", "RtlDecompressBufferEx"])
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        if self.Info.is_64bit():
            pattern = struct.pack("H", self.fe.getRegVal("rcx"))
        else:
            reg_esp = self.fe.getRegVal("esp")
            pattern = self.fe.getEmuBytes(reg_esp, 0x2)  # Using 0x2 because this is a WORD field
        return pat.find(pattern)
