"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: SmkmStoreMetadata.py
Description: The SmkmStoreMetadata class corresponds to the Windows 10 SMKM_STORE_METADATA
structure. Each SMKM_STORE_METADATA structure correlates to a single store, of the possible
1024 stores (1607+).
"""
import logging

from RamPack import RamPack


class SmkmStoreMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM_STORE_METADATA.Size: 0x{0:x}".format(self.Info.arch_fns[arch]['ssm_sizeof'](self)))
        self.logger.info("SMKM_STORE_METADATA.pSmkmStore: 0x{0:x}".format(self.Info.arch_fns[arch]['ssm_smkmstore'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def ssm_sizeof(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        reg_ax = 'rax' if self.Info.is_64bit() else 'eax'
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        reg_dx = 'rdx' if self.Info.is_64bit() else 'edx'
        regState = {reg_cx:lp_addr_smkmstoremgr, reg_dx:num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal(reg_ax) + 1

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def ssm_smkmstore(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmIoCtxQueueWork", ["SmWorkItemQueue", "SmStWorkItemQueue"])
        self.fe.iterate([endAddr], self.tHook)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        return self.fe.getRegVal(reg_cx)
