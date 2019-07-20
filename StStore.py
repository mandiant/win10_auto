import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from RamPack import RamPack


class StStore(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_STORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("ST_STORE.StDataMgr: 0x{0:x}".format(self.st_data_mgr()))
        return

    def sizeof(self):
        return

    def st_data_mgr(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?StStart", "StDmStart")
        self.fe.iterate([endAddr], self.tHook)
        return self.fe.uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX)
