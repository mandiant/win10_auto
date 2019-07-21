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
        for va, name in idautils.Names():
            if "?SmGlobals" in name:
                return va - idaapi.get_imagebase()
        self.logger.error("SmGlobals could not be resolved.")
        return None

    @RamPack.Info.arch32
    def m32_mmpagingfile(self):
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if "*4]" in op1:
                return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None

    @RamPack.Info.arch64
    def m64_mmpagingfile(self):
        (addr, name) = self.find_ida_name("MmStoreCheckPagefiles")

        for insn_addr, insn, op0, op1 in self.iter_fn(addr):
            if insn == "lea":
                if idc.get_operand_type(insn_addr, 1) == idc.o_mem:
                    return idc.get_operand_value(insn_addr, 1) - idaapi.get_imagebase()

        self.logger.error("MmPagingFile could not be resolved.")
        return None