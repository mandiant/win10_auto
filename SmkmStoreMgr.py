import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from RamPack import RamPack


class SmkmStoreMgr(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        self.logger.info("SMKM_STORE_MGR.Smkm: 0x{0:x}".format(self.smkm()))
        self.logger.info("SMKM_STORE_MGR.BTreeGlobalStore: 0x{0:x}".format(self.key_to_storetree()))

    def smkm(self):
        return 0  # constant across win10

    def vlock(self):
        (startAddr, endAddr) = self.locate_call_in_fn("SmFeReadInitiate", "ExAcquirePushLockSharedEx")

        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset
        addr_smkmstoremgr = 0x1000
        regState = {'ecx': addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr

    def key_to_storetree(self):
        (startAddr, endAddr) = self.locate_call_in_fn("?SmFeCheckPresent",
                                                      "?BTreeSearchKey@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY")
        # @start ecx is SmkmStoreMgr and instantiated to 0.
        # @end ecx is the pushlock argument, diff to get struct offset
        addr_smkmstoremgr = 0x1000
        regState = {'ecx': addr_smkmstoremgr}
        self.fe.emulateRange(startAddr, registers=regState, endAddr=endAddr)
        return self.fe.getRegVal('ecx') - addr_smkmstoremgr