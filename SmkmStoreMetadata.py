"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: SmkmStoreMetadata.py

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


class SmkmStoreMetadata(Tools):
    """
    The SmkmStoreMetadata class corresponds to the Windows 10 SMKM_STORE_METADATA
    structure. Each SMKM_STORE_METADATA structure correlates to a single store, of
    the possible 1024 stores (1607+).
    """
    def __init__(self, loglevel=logging.INFO):
        self.tools = super(SmkmStoreMetadata, self).__init__()
        self.logger = logging.getLogger("SMKM_STORE_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
         Architecture agnostic function used to dump all located fields.
         """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("Size: {0:#x}".format(self.Info.arch_fns[arch]['ssm_sizeof'](self)))
        self.logger.info("pSmkmStore: {0:#x}".format(self.Info.arch_fns[arch]['ssm_smkmstore'](self)))
        return

    @Tools.Info.arch32
    @Tools.Info.arch64
    def ssm_sizeof(self):
        """
        The size of the SMKM_STORE_METADATA structure is important due to its' presence as an array
        of size 32. Traversing the array via index requires you to know the size. The SmKmSToreRefFromStoreIndex
        function does this traversal and is the ideal candidate. The emulateRange function is used here
        because we are traversing the entire function, not stopping at a certain point. We preset
        the Store to 0 and check the value in the *AX register upon completion. Disassembly snippet from
        Windows 10 1809 x86 shown below.

        SmKmStoreRefFromStoreIndex      _SmKmStoreRefFromStoreIndex@8 proc near ;
        SmKmStoreRefFromStoreIndex                      mov     eax, edx
        SmKmStoreRefFromStoreIndex+2                    shr     eax, 5
        SmKmStoreRefFromStoreIndex+5                    mov     ecx, [ecx+eax*4]
        SmKmStoreRefFromStoreIndex+8                    test    ecx, ecx
        SmKmStoreRefFromStoreIndex+A                    jz      short loc_4C7D41
        SmKmStoreRefFromStoreIndex+C                    and     edx, 1Fh
        SmKmStoreRefFromStoreIndex+F                    imul    eax, edx, 14h
        SmKmStoreRefFromStoreIndex+12                   add     eax, ecx
        SmKmStoreRefFromStoreIndex+14                   retn
        """
        (fn_addr, fn_name) = self.find_ida_name("SmKmStoreRefFromStoreIndex")

        addr_smkmstoremgr = 0x1000
        lp_addr_smkmstoremgr = self.fe.loadBytes("".ljust(0x1000, "\xFF"))

        # EDX can be checked at the end for the #-of-stores mask
        num_store = 0x1
        reg_ax = 'rax' if self.Info.is_64bit() else 'eax'
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        reg_dx = 'rdx' if self.Info.is_64bit() else 'edx'
        regState = {reg_cx:lp_addr_smkmstoremgr, reg_dx:num_store}
        self.fe.emulateRange(fn_addr, registers=regState)
        return self.fe.getRegVal(reg_ax) + 1

    @Tools.Info.arch32
    @Tools.Info.arch64
    def ssm_smkmstore(self):
        """
        This field is a pointer to an SMKM_STORE structure. See SMKM_STORE for additional information.
        This function relies on the first argument to SmStWorkItemQueue remaining constant. Disassembly
        snippet from Windows 10 1809 x86 shown below.

        SmIoCtxQueueWork+93     call    _SmKmStoreRefFromStoreIndex@8
        SmIoCtxQueueWork+98     push    0               ; KIRQL
        SmIoCtxQueueWork+9A     mov     edx, edi
        SmIoCtxQueueWork+9C     mov     ecx, [eax]
        SmIoCtxQueueWork+9E     call    _SmWorkItemQueue@12
        """
        (startAddr, endAddr) = self.locate_call_in_fn("SmIoCtxQueueWork", ["SmWorkItemQueue", "SmStWorkItemQueue"])
        self.fe.iterate([endAddr], self.tHook)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        return self.fe.getRegVal(reg_cx)
