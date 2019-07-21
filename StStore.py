"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: StStore.py
Description: The StStore class corresponds to the Windows 10 ST_STORE
structure. The ST_STORE structure is nested within SMKM_STORE and represents a single store.
The nested structure ST_DATA_MGR is the only field of interest in page retrieval.
"""
import logging

from RamPack import RamPack


class StStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("ST_STORE.StDataMgr: 0x{0:x}".format(self.Info.arch_fns[arch]['ss_stdatamgr'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def ss_stdatamgr(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StStart", "StDmStart")
        self.fe.iterate([endAddr], self.tHook)
        reg_dx = 'rdx' if self.Info.is_64bit() else 'edx'
        return self.fe.getRegVal(reg_dx)
