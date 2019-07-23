"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: SmkmStoreMgr.py

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

from Tools import Tools


class SmkmStoreMgr(Tools):
    """
    The SmkmStoreMgr class corresponds to the Windows 10 SMKM_STORE_MGR
    structure. The SMKM_STORE_MGR structure contains information about all the stores
    being used by the system. The structure contains a B_TREE of all SM_PAGE_KEYs
    being used, as well as a nested structure (SMKM) which is the last global structure
    in the path to the compressed page.
    """
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMKM_STORE_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
        Architecture agnostic function used to dump all located fields.
        """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("SMKM_STORE_MGR.sSmKm: {0:#x}".format(self.Info.arch_fns[arch]['sksm_smkm'](self)))
        self.logger.info("SMKM_STORE_MGR.sGlobalTree: {0:#x}".format(self.Info.arch_fns[arch]['sksm_globaltree'](self)))
        return

    @Tools.Info.arch32
    @Tools.Info.arch64
    def sksm_smkm(self):
        """
        This structure is nested within SMKM_STORE_MGR at offset 0. See SMKM for additional
        information. Returning offset zero until an update is needed.
        """
        return 0  # constant across win10

    @Tools.Info.arch32
    @Tools.Info.arch64
    def sksm_globaltree(self):
        """
        This B+TREE is nested within the SMKM_STORE_MGR and contains leaf nodes of type
        SMKM_FRONTEND_ENTRY. The SMKM_FRONTEND_ENTRY structure contains the SM_PAGE_KEY's
        store index and creation flags. This function traverses SmFeCheckPresent up until
        BTreeSearchKey. It relies on the BTreeSearchKey function being stable in that the
        B+TREE is the first argument.
        """
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
