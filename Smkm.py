import logging
import struct

from RamPack import RamPack


class Smkm(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump32(self):
        self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(self.Info.arch_fns['x86']['sk32_storemetadataarray'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    def sk32_storemetadataarray(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", addr_smkmstoremgr))
        num_store = 0x0
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr