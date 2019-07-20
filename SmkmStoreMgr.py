import logging
from RamPack import RamPack


class SmkmStoreMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump32(self):
        self.logger.info("SMKM_STORE_MGR.Smkm: 0x{0:x}".format(self.Info.arch_fns['x86']['sksm32_smkm'](self)))
        self.logger.info("SMKM_STORE_MGR.BTreeGlobalStore: 0x{0:x}".format(self.Info.arch_fns['x86']['sksm32_globaltree'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    def sksm32_smkm(self):
        return 0  # constant across win10

    @RamPack.Info.arch32
    def sksm32_globaltree(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmFeCheckPresent",
                                                      "?BTreeSearchKey@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY")
        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset
        addr_smkmstoremgr = 0x1000

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData["EmuHelper"].uc.reg_write(userData["EmuHelper"].regs["cx"], addr_smkmstoremgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr