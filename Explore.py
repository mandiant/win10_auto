import logging
import struct

from Tools import Tools

class Explore(Tools):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("EXPLORE")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def explore(self):
        (fn_addr, fn_name) = self.find_ida_name("SmKeyConvert")
        #lp_pte = self.fe.loadBytes("\x84\x20\x00\x00\xdf\x6e\x02\x00")

        lp_pte = self.fe.loadBytes(struct.pack("<Q", 0x2000000000026edf))
        regState = {'rcx':lp_pte}
        self.fe.emulateRange(fn_addr, registers=regState, instructionHook=self.eHookDbg)
        return None