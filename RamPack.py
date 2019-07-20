import logging
import string

import idc
import idautils

import capstone

from flare_emu import flare_emu


class RamPack():
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("RamPack")  # TODO overwritten by child logs
        self.logger.setLevel(loglevel)
        return

    def find_ida_name(self, fn_name):
        self.logger.debug("Searching for {0}...".format(fn_name))
        for name_addr in idautils.Names():
            if fn_name in name_addr[1]:
                self.logger.debug("found {0} @ {1}".format(name_addr[1], hex(name_addr[0])))
                return name_addr
        self.logger.error("{0} NOT FOUND".format(fn_name))

    def get_cs(self):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        return cs

    def get_flare_emu(self, loglevel=logging.INFO):
        fe = flare_emu.EmuHelper(loglevel=loglevel)
        return fe

    def iter_fn(self, addr):
        cs = self.get_cs()
        for insn_addr in idautils.FuncItems(addr):
            for insn in cs.disasm(idc.GetManyBytes(insn_addr, idc.ItemSize(insn_addr)), insn_addr):
                yield insn

    def locate_call_in_fn(self, fns_start, fns_call):
        if type(fns_start) is not list:
            fns_start = [fns_start]
        if type(fns_call) is not list:
            fns_call = [fns_call]

        for fn_start in fns_start:
            for fn_call in fns_call:
                (addr_start, name_start) = self.find_ida_name(fn_start)
                (addr_end, name_end) = self.find_ida_name(fn_call)

                for insn in self.iter_fn(addr_start):
                    if insn.id == capstone.x86.X86_INS_CALL:
                        if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                            call_offset = insn.operands[0].imm
                            if call_offset == addr_end:
                                addr_end = insn.address
                                self.logger.debug("located {0} in {1} @ 0x{2:x}".format(name_end, name_start, addr_end))
                                return (addr_start, addr_end)
                self.logger.error("Failed to locate {0} within {1}".format(name_end, name_start))

        self.logger.error("locate_call_in_fn failed")
        return (None, None)

    @staticmethod
    def patgen(buf_len, size=4):
        pat = ""
        symbols = "`~!@#$%^&*()-=_+[]\{}|;':,./<>?"
        if size == 4:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        for s in symbols:
                            pat += "".join([u, l, i, s])
                            buf_len -= 3
                            if buf_len < 0:
                                return pat
        elif size == 3:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    for i in string.digits:
                        pat += "".join([u, l, i])
                        buf_len -= 3
                        if buf_len < 0:
                            return pat

        elif size == 2:
            for u in string.ascii_uppercase:
                for l in string.ascii_lowercase:
                    pat += "".join([u, l])
                    buf_len -= 3
                    if buf_len < 0:
                        return pat

        else:
            self.logger.error("Unsupported size fed to pattern generator")

    """
    Use with instructionHook callback to get a disassembly + reg dump
    """

    def eHookDbg(self, uc, address, size, user_data):
        fe = user_data['EmuHelper']
        dis = idc.GetDisasm(address)
        fe.logger.info("\n".join([dis, fe.getEmuState()]))
        return

    def eHookDerefMonitor(self, uc, address, size, user_data):
        # possible TODO
        return

    def eHookTrace(self, uc, address, size, user_data):
        if not user_data.has_key('cs'):
            user_data['cs'] = RamPack().get_cs()
            RamPack().logger.debug("created cs instance")
        if not user_data.has_key('trace'):
            user_data['trace'] = []

        ctx = uc.context_save()
        for insn in user_data['cs'].disasm(idc.GetManyBytes(address, idc.ItemSize(address)), address):
            mem_regions = [reg_start for (reg_start, reg_end, reg_perms) in uc.mem_regions()]
            user_data['trace'].append({'cs_insn': insn, 'uc_ctx': ctx, 'mem_regions': tuple(mem_regions)})

        # self.fe_userdata['trace'] = copy.deepcopy(user_data['trace']) IDA falls over
        self.fe_userdata = user_data  # TODO - Objects in dictionary may not be accurate due to linking
        return

    def tHook(self, fe, address, argv, userData):
        RamPack().logger.debug("Hit target @ {0}".format(hex(address)))
        return