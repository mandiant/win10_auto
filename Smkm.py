"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: Smkm.py

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
import struct

from Tools import Tools


class Smkm(Tools):
    """
    The Smkm class corresponds to the Windows 10 SMKM structure.The SMKM
    structure is the last global structure used before relying on store-specific
    structures to locate the compressed page.
    """
    def __init__(self, loglevel=logging.INFO):
        self.tools = super(Smkm, self).__init__()
        self.logger = logging.getLogger("SMKM")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
        Architecture agnostic function used to dump all located fields.
        """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SmkmStoreMetadataArray: {0:#x}".format(self.Info.arch_fns[arch]['sk_storemetadataarray'](self)))
        return

    @Tools.Info.arch32
    @Tools.Info.arch64
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