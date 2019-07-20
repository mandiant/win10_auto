import logging
import struct

from RamPack import RamPack


class Smkm(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(self.Info.arch_fns[arch]['sk_storemetadataarray'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sk_storemetadataarray(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", 0x1000))
        num_store = 0x0
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        reg_dx = 'rdx' if self.Info.is_64bit() else 'edx'
        regState = {reg_cx:lp_addr_smkmstoremgr, reg_dx:num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal(reg_cx) - lp_addr_smkmstoremgr