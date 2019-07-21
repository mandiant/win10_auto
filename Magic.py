"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: Magic.py
Description: There are two magic offsets on which the extraction of compressed memory
relies on. The pointer to the SM_GLOBALS structure and the MmPagingFile pointer (no
longer exported) containing an array of pointers to nt!_MMPAGING_FILE structures. This
file locates them & extracts them.
"""
import logging

import idc
import idautils
import idaapi

from RamPack import RamPack


class Magic(RamPack):
    cs = None

    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("Magic")
        self.logger.setLevel(loglevel)
        return

    def _dump(self):
        """
         Architecture agnostic function used to dump all located fields.
         """
        if self.Info.is_64bit():
            self.logger.info("MAGIC.SmGlobals: 0x{0:x}".format(self.Info.arch_fns['x64']['m_smglobals'](self)))
            self.logger.info("MAGIC.MmPagingFile: 0x{0:x}".format(self.Info.arch_fns['x64']['m64_mmpagingfile'](self)))
        else:
            self.logger.info("MAGIC.SmGlobals: 0x{0:x}".format(self.Info.arch_fns['x86']['m_smglobals'](self)))
            self.logger.info("MAGIC.MmPagingFile: 0x{0:x}".format(self.Info.arch_fns['x86']['m32_mmpagingfile'](self)))
        return

    def _dump64(self):
        return

    @RamPack.Info.arch32
    @RamPack.Info.arch64
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

    @RamPack.Info.arch32
    def m32_mmpagingfile(self):
        """
        The MmPagingFile pointer can be defined as PVOID *MMPAGING_FILE[16]. Support for locating this
        pointer is not mandatory, but essential to verify if an MMPAGING_FILE structure corresponds
        to a virtual store. Although this pointer was previously exported as nt!MmPagingFile in Windows
        7, the pointer has not been exported by any Windows 10 kernel to date. This function traverses
        MiVaIsPageFileHash and stops at the first instance of an memory dereference by index. The
        signature appears to be fragile but has worked from 1607-1809.
        """
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if "*4]" in op1:
                return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None

    @RamPack.Info.arch64
    def m64_mmpagingfile(self):
        """
       The MmPagingFile pointer can be defined as PVOID *MMPAGING_FILE[16]. Support for locating this
        pointer is not mandatory, but essential to verify if an MMPAGING_FILE structure corresponds
        to a virtual store. Although this pointer was previously exported as nt!MmPagingFile in Windows
        7, the pointer has not been exported by any Windows 10 kernel to date. This function traverses
        MmStorecheckPagefiles. The same signature as x86 could not be used due to compiler optimzations
        using the LEA instruction to get the address of the global variable.
        """
        (addr, name) = self.find_ida_name("MmStoreCheckPagefiles")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if insn == "lea":
                if idc.get_operand_type(insn_addr, 1) == idc.o_mem:
                    return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None