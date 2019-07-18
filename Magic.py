import logging
import struct
import string

import idc
import idautils
import idaapi

import capstone
import unicorn

from flare_emu import flare_emu

from RamPack import RamPack


class Magic(RamPack):
    cs = None

    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("Magic")
        self.logger.setLevel(loglevel)
        self.cs = self.get_cs()
        return

    def _dump(self):
        smglobals = self.smglobals_ida()
        pagefilearray = self.mmpagefilearray_ida()
        self.logger.info("MAGIC.SmGlobals: 0x{0:x}".format(smglobals))
        self.logger.info("MAGIC.MmPagingFile: 0x{0:x}".format(pagefilearray))

    # Requirements: PDB & IDA
    def smglobals_ida(self):
        for va, name in idautils.Names():
            if "?SmGlobals" in name:
                return va - idaapi.get_imagebase()
        self.logger.error("SmGlobals could not be resolved.")
        return None

    # Requirements: PDB & IDA
    def mmpagefilearray_ida(self):
        (addr, name) = self.find_ida_name("MiVaIsPageFileHash")

        for insn in self.iter_fn(addr):
            if len(insn.operands) == 2:
                if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                    if insn.operands[1].mem.disp:
                        if insn.sib:
                            if insn.operands[1].mem.disp != 0:
                                self.logger.debug("offset %x" % insn.operands[1].mem.disp)
                            if insn.sib_base != 0:
                                self.logger.debug("sib_base: %s" % (insn.reg_name(insn.sib_base)))
                            if insn.sib_index != 0:
                                self.logger.debug("sib_index: %s" % (insn.reg_name(insn.sib_index)))
                            if insn.sib_scale != 0:
                                self.logger.debug("sib_scale: %d" % (insn.sib_scale))

                            return insn.operands[1].mem.disp
        self.logger.error("MmPagingFile could not be resolved.")
        return None