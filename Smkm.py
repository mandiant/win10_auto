"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: Smkm.py
Description: The Smkm class corresponds to the Windows 10 SMKM structure.The
SMKM structure is the last global structure used before relying on store-specific
structures to locate the compressed page.
"""
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
        """
        Architecture agnostic function used to dump all located fields.
        """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM.SmkmStoreMetadataArray: 0x{0:x}".format(self.Info.arch_fns[arch]['sk_storemetadataarray'](self)))
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
    def sk_storemetadataarray(self):
        """
        This is an array of 32 pointers, each of which points to an array of 32 SMKM_STORE_METADATA
        structures. The SmKmStoreRefFromStoreIndex function traverses the pointer array. This
        signature asks the function to locate Store 0. The value stored in *CX at the end of
        function emulation corresponds to the offset of the StoreMetadataArray.
        """
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")
        lp_addr_smkmstoremgr = self.fe.loadBytes(struct.pack("<I", 0x1000))
        num_store = 0x0
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        reg_dx = 'rdx' if self.Info.is_64bit() else 'edx'
        regState = {reg_cx:lp_addr_smkmstoremgr, reg_dx:num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal(reg_cx) - lp_addr_smkmstoremgr