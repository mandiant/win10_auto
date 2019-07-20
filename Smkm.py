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
        if self.Info.is_64bit():
            self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(self.Info.arch_fns['x64']['sk_storemetadataarray'](self)))
        else:
            self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(self.Info.arch_fns['x86']['sk_storemetadataarray'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sk_storemetadataarray(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", 0x1000))
        num_store = 0x0
        if self.Info.is_64bit():
            reg_cx = 'rcx'
            reg_dx = 'rdx'
        else:
            reg_cx = 'ecx'
            reg_dx = 'edx'
        regState = {reg_cx:lp_addr_smkmstoremgr, reg_dx:num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal(reg_cx) - lp_addr_smkmstoremgr