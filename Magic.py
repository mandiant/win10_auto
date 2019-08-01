"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: Magic.py

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

import idc
import idautils
import idaapi

from Tools import Tools


class Magic(Tools):
    """
    There are two magic offsets on which the extraction of compressed memory
    relies on. The pointer to the SM_GLOBALS structure and the MmPagingFile pointer (no
    longer exported) containing an array of pointers to nt!_MMPAGING_FILE structures. This
    file locates them & extracts them.
    """
    cs = None

    def __init__(self, loglevel=logging.INFO):
        self.tools = super(Magic, self).__init__()
        self.logger = logging.getLogger("Magic")
        self.logger.setLevel(loglevel)
        return

    def _dump(self):
        """
         Architecture agnostic function used to dump all located fields.
         """
        if self.Info.is_64bit():
            self.logger.info("SmGlobals: {0:#x}".format(self.Info.arch_fns['x64']['m_smglobals'](self)))
            self.logger.info("MmPagingFile: {0:#x}".format(self.Info.arch_fns['x64']['m64_mmpagingfile'](self)))
        else:
            self.logger.info("SmGlobals: {0:#x}".format(self.Info.arch_fns['x86']['m_smglobals'](self)))
            self.logger.info("MmPagingFile: {0:#x}".format(self.Info.arch_fns['x86']['m32_mmpagingfile'](self)))
        return

    def _dump64(self):
        return

    @Tools.Info.arch32
    @Tools.Info.arch64
    def m_smglobals(self):
        """
         The SM_GLOBALS structure contains information about all stores being used by the system.
         It can be located via the nt!SmGlobals symbol. Locating this structure is the fastest way
         to begin the page retrieval process. This function searches for the symbol in IDA's namespace.
         It is available in the ntoskrnl's PDB.
        """
        for va, name in idautils.Names():
            if "?SmGlobals" in name:
                return va - idaapi.get_imagebase()
        self.logger.error("SmGlobals could not be resolved.")
        return None

    @Tools.Info.arch32
    def m32_mmpagingfile(self):
        """
        The MmPagingFile pointer can be defined as PVOID *MMPAGING_FILE[16]. Support for locating this
        pointer is not mandatory, but essential to verify if an MMPAGING_FILE structure corresponds
        to a virtual store. Although this pointer was previously exported as nt!MmPagingFile in Windows
        7, the pointer has not been exported by any Windows 10 kernel to date. This function traverses
        MiVaIsPageFileHash and stops at the first instance of an memory dereference by index. The
        signature appears to be fragile but has worked from 1607-1809. Disassembly snippet from
        Windows 10 1809 x86 shown below.

        MiVaIsPageFileHash(x,x)      _MiVaIsPageFileHash@8 proc near         ;
        MiVaIsPageFileHash(x,x)                      mov     edi, edi
        MiVaIsPageFileHash(x,x)+2                    push    ebx
        MiVaIsPageFileHash(x,x)+3                    push    esi
        MiVaIsPageFileHash(x,x)+4                    push    edi
        MiVaIsPageFileHash(x,x)+5                    mov     edi, Count
        MiVaIsPageFileHash(x,x)+B                    xor     ecx, ecx
        MiVaIsPageFileHash(x,x)+D                    mov     ebx, edx
        MiVaIsPageFileHash(x,x)+F                    test    edi, edi
        MiVaIsPageFileHash(x,x)+11                   jnz     short loc_4DC5C7
        MiVaIsPageFileHash(x,x)+19   loc_4DC5C7:                             ;
        MiVaIsPageFileHash(x,x)+19                   mov     esi, dword_6A8614[ecx*4]
        """
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if "*4]" in op1:
                return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None

    @Tools.Info.arch64
    def m64_mmpagingfile(self):
        """
       The MmPagingFile pointer can be defined as PVOID *MMPAGING_FILE[16]. Support for locating this
        pointer is not mandatory, but essential to verify if an MMPAGING_FILE structure corresponds
        to a virtual store. Although this pointer was previously exported as nt!MmPagingFile in Windows
        7, the pointer has not been exported by any Windows 10 kernel to date. This function traverses
        MmStorecheckPagefiles. The same signature as x86 could not be used due to compiler optimzations
        using the LEA instruction to get the address of the global variable. Disassembly snippet from
        Windows 10 1809 x64 shown below.

        MmStoreCheckPagefiles      MmStoreCheckPagefiles proc near         ;
        MmStoreCheckPagefiles                      mov     r9d, cs:Count
        MmStoreCheckPagefiles+7                    xor     r8d, r8d
        MmStoreCheckPagefiles+A                    test    r9d, r9d
        MmStoreCheckPagefiles+D                    jz      short loc_14072F307
        MmStoreCheckPagefiles+F                    lea     eax, [r8+1]
        MmStoreCheckPagefiles+13                   lea     r10, unk_14043E5E0
        """
        (addr, name) = self.find_ida_name("MmStoreCheckPagefiles")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if insn == "lea":
                if idc.get_operand_type(insn_addr, 1) == idc.o_mem:
                    return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None