"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: MiHardwareState.py

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

import idaapi

from Tools import Tools


class MiHardwareState(Tools):
    """
    The _MI_HARDWARE_STATE structure is available as an export in Windows 10.
    As of Win10.1803.x64, the derivation of the SM_PAGE_KEY (Store Manager key)
    has changed to leverage both the MMPTE_SOFTWARE.SwizzleBit and
    MI_HARDWARE_STATE.InvalidPteMask fields.
    """
    def __init__(self, loglevel=logging.INFO):
        self.tools = super(MiHardwareState, self).__init__()
        self.logger = logging.getLogger("MI_HARDWARE_STATE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
        Architecture agnostic function used to dump all located fields.
        """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("MI_HARDWARE_STATE.InvalidPteMask: {0:#x}".format(self.Info.arch_fns[arch]['mhs_invalidptemask'](self)))
        return

    @Tools.Info.arch64
    def mhs_invalidptemask(self):
        """
        The InvalidPteMask is used in the derivation of the SM_PAGE_KEY in Win10.1803.x64+.
        """
        (fn_addr, fn_name) = self.find_ida_name("MiSwizzleInvalidPte")
        mHookData = {'offset':None}

        def mHook(uc, accessType, memAccessAddress, memAccessSize, memValue, userData):
            if mHookData['offset']:
                return

            if accessType == 16:  # UC_MEM_READ
                self.logger.debug("Mem read @ 0x{0:x}: {1}".format(memAccessAddress, memValue))
                mHookData['offset'] = memAccessAddress

        self.fe.emulateRange(fn_addr, memAccessHook=mHook)
        return mHookData['offset'] - idaapi.get_imagebase()
