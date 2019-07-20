import logging
import string

import idc
import idautils
import idaapi

from flare_emu import flare_emu


class RamPack():
    class Info():
        arch_fns = {'x86': {}, 'x64': {}}

        @classmethod
        def arch32(self, fn):
            self.arch_fns['x86'][fn.__name__] = fn
            return fn

        @classmethod
        def arch64(self, fn):
            self.arch_fns['x64'][fn.__name__] = fn
            return fn

        @staticmethod
        def is_64bit():
            info = idaapi.get_inf_structure()
            return info.is_64bit()

    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("RamPack")  # TODO overwritten by child logs
        self.logger.setLevel(loglevel)
        self.info = self.Info()
        return

    def find_ida_name(self, fn_name):
        self.logger.debug("Searching for {0}...".format(fn_name))
        for name_addr in idautils.Names():
            if fn_name in name_addr[1]:
                self.logger.debug("found {0} @ {1}".format(name_addr[1], hex(name_addr[0])))
                return name_addr
        self.logger.error("{0} NOT FOUND".format(fn_name))
        return None

    def get_flare_emu(self, loglevel=logging.INFO):
        fe = flare_emu.EmuHelper(loglevel=loglevel)
        return fe

    def iter_fn(self, startAddr):
        endAddr = idc.GetFunctionAttr(startAddr, idc.FUNCATTR_END)
        for head in idautils.Heads(startAddr, endAddr):
            yield head, idc.GetDisasm(head).split()[0], idc.GetOpnd(head, 0), idc.GetOpnd(head, 1)

    def locate_call_in_fn(self, fns_start, fns_call):
        if type(fns_start) is not list:
            fns_start = [fns_start]
        if type(fns_call) is not list:
            fns_call = [fns_call]

        for fn_start in fns_start:
            (addr_start, name_start) = self.find_ida_name(fn_start)
            for fn_call in fns_call:
                (addr_end, name_end) = self.find_ida_name(fn_call)

                for insn_addr, insn, op0, op1 in self.iter_fn(addr_start):
                    if insn == "call":
                        if op0 == name_end:
                            self.logger.debug("located {0} in {1} @ {2:#x}".format(name_end, name_start, addr_end))
                            return addr_start, insn_addr

                self.logger.debug("Failed to locate {0} within {1}".format(name_end, name_start))

        self.logger.error("locate_call_in_fn failed")
        return None, None

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