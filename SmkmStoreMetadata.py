import logging

from RamPack import RamPack


class SmkmStoreMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump32(self):
        self.logger.info("SMKM_STORE_METADATA.Size: 0x{0:x}".format(self.Info.arch_fns['x86']['sizeof'](self)))
        self.logger.info("SMKM_STORE_METADATA.pSmkmStore: 0x{0:x}".format(self.Info.arch_fns['x86']['smkm_store'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    def sizeof(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        regState = {'ecx':lp_addr_smkmstoremgr, 'edx':num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal('eax') + 1

    @RamPack.Info.arch32
    def smkm_store(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmIoCtxQueueWork", ["SmWorkItemQueue", "SmStWorkItemQueue"])
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.getRegVal('ecx')
