import logging
from RamPack import RamPack


class SmkmStoreMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM_STORE_MGR.sSmKm: {0:#x}".format(self.Info.arch_fns[arch]['sksm_smkm'](self)))
        self.logger.info("SMKM_STORE_MGR.sGlobalTree: {0:#x}".format(self.Info.arch_fns[arch]['sksm_globaltree'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sksm_smkm(self):
        return 0  # constant across win10

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sksm_globaltree(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmFeCheckPresent",
                                                      "?BTreeSearchKey@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY")
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'

        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset
        addr_smkmstoremgr = 0x1000

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData["EmuHelper"].uc.reg_write(userData["EmuHelper"].regs["cx"], addr_smkmstoremgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        return self.fe.getRegVal(reg_cx) - addr_smkmstoremgr
