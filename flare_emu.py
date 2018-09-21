############################################
# Author: James T. Bennett
#
# flare-emu combines Unicorn and IDA to provide emulation support for reverse engineers
# Currently supports 32-bit and 64-bit x86, ARM, and ARM64
# Dependencies:
# https://github.com/unicorn-engine/unicorn
############################################

from __future__ import print_function
from idc import *
from idaapi import *
from idautils import *
from idc import get_segm_name
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from copy import deepcopy
import time
import logging
import struct
import pickle
import types

IDADIR = idadir("")
PAGESIZE = 0x1000
PAGEALIGNCHECK = 0xfff
DEBUG = 0

class EmuHelper():
    def __init__(self):        
        self.logger = logging.getLogger("flare_emu")
        self.stack = 0
        self.stackSize = 0x2000
        self.size_DWORD = 4
        self.size_pointer = 0
        self.callMnems = ["call", "BL", "BLX", "BLR", "BLXEQ", "BLEQ", "BLREQ"]
        self.paths = {}
        self.filetype = "UNKNOWN"
        self.mu = None
        self.h_userhook = None
        self.h_codehook = None
        self.h_memhook = None
        self.h_inthook = None
        self.user_storage = {}
        self.enteredBlock = False
        self.initEmuHelper()
        self.reloadBinary()

    # startAddr: address to start emulation
    # registerState: a dict whose keys are register names and values are register values, all unspecified registers 
    # will be initialized to 0
    # argv: a list of arg values to be setup on the stack before emulation, if X86 you must account for SP+0 
    # (return address)
    # for the argv and registerState parameters, specifying a string will allocate memory, write the string to it, and
    # write a pointer to that memory in the specified register/arg.
    # emuHook: user-defined instruction hook function to register with emulator
    # hookData: user-defined data to be made available in instruction hook function, care must be taken to not use key
    # names already used by flare_emu in userData dictionary
    # endAddr: address to end emulation. if not provided, emulation stops when starting function is exited (must end 
    # with return instruction)
    # skipCalls: emulator will skip over call instructions and adjust the stack accordingly, defaults to True. 
    # emulateRange will always skip over calls to empty memory
    # callHook: callback function that will be called whenever the emulator encounters a "call" instruction. keep in 
    # mind your skipCalls value and that emulateRange will always skip over calls to empty memory
    # returns the emulation object in its state after the emulation completes
    def emulateRange(self, startAddr, registerState=None, argv=None, emuHook=None, callHook=None, hookData=None, endAddr=None, 
        skipCalls=True):
        assert type(startAddr) is types.LongType
        if registerState:
            assert type(registerState) is types.DictType
        else:
             registerState = {}

        if argv:
            assert type(argv) is types.ListType
        else:
            argv = []

        if emuHook:
            assert type(emuHook) is types.FunctionType
        
        if callHook:
            assert type(callHook) is types.FunctionType

        userData = {"EmuHelper": self, "funcStart": get_func_attr(startAddr, FUNCATTR_START), "funcEnd": 
        get_func_attr(startAddr, FUNCATTR_END), "skipCalls": skipCalls, "endAddr": endAddr, "func_t": 
        get_func(startAddr), "callHook": callHook}
        if hookData is not None:
            userData.update(hookData)
        mu = self.mu
        self._prepEmuContext(registerState, argv)
        self.resetEmuHooks()
        self.h_codehook = mu.hook_add(
            UC_HOOK_CODE, self._emulateRange_codehook, userData)
        if emuHook is not None:
            self.h_userhook = mu.hook_add(UC_HOOK_CODE, emuHook, userData)
        self.h_memhook = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                                     UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid, userData)
        self.h_inthook = mu.hook_add(
            UC_HOOK_INTR, self._hook_interrupt, userData)
        if self.arch == UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        mu.emu_start(startAddr, userData["funcEnd"])
        return mu

    # target: finds first path through function to target using depth first search for each address in list, if a 
    # single address is specified, does so for each xref to target address
    # emulates each target's function, forcing path to target, then executes callback function providing emu object 
    # and arguments
    # emuHook: user-defined instruction hook to run AFTER guided_hook that forces execution
    # hookData: user-defined data to be made available in instruction hook function, care must be taken to not use key
    # names already used by flare_emu in userData dictionary
    # preEmuCallback: a callback that is called BEFORE each emulation run
    # callHook: a callback that is called whenever the emulator encounters a "call" instruction. hook or no, after a 
    # call instruction, the program counter is advanced to the next instruction and the stack is automatically cleaned 
    # up
    # resetEmuMem: if set to True, unmaps all allocated emulator memory and reloads the binary from the IDB into 
    # emulator memory before each emulation run. can significantly increase script run time, defaults to False
    def iterate(self, target, targetCallback, preEmuCallback=None, callHook=None, emuHook=None, hookData=None, 
        resetEmuMem=False):
        if target is None:
            return
        
        targetInfo = {}
        if type(target) in [int, long]:
            self.logger.debug("iterate target function: %s" %
                          self.hexString(target))
            xrefs = list(XrefsTo(target))
            i = 1
            for x in xrefs:
                # get unique functions from xrefs that we need to emulate
                funcStart = get_func_attr(x.frm, FUNCATTR_START)
                if funcStart == BADADDR:
                    continue
                if self.safe_print_insn_mnem(x.frm) not in ["call", "jmp", "BL", "BLX", "B", "BLR"]:
                    continue

                # if maxPaths > 1:
                #    self.logger.debug("getting up to %d paths to %s, %d of %d" % (maxPaths, self.hexString(x.frm), i, 
                #       len(xrefs)))
                #    targetInfo[x.frm] = self.getPaths(x.frm, maxPaths)
                # else:
                self.logger.debug("getting a path to %s, %d of %d" %
                              (self.hexString(x.frm), i, len(xrefs)))
                flow, paths = self.getPath(x.frm)
                if flow is not None:
                    targetInfo[x.frm] = (flow, paths)
                i += 1
        elif type(target) is list:
            i = 1
            for t in target:
                # if maxPaths > 1:
                #    self.logger.debug("getting up to %d paths to %s, %d of %d" % (maxPaths, self.hexString(t), i, 
                #       len(target)))
                #    targetInfo[t] = self.getPaths(t, maxPaths)
                # else:
                self.logger.debug("getting a path to %s, %d of %d" %
                              (self.hexString(t), i, len(target)))
                flow, paths = self.getPath(t)
                if flow is not None:
                    targetInfo[t] = (flow, paths)
                i += 1
        if len(targetInfo) <= 0:
            self.logger.debug("no targets to iterate")
            return
        
        # with open("targetinfo.pickle", "wb") as po:
        #    pickle.dump(targetInfo, po)
        # with open("targetinfo.pickle", "rb") as po:
        #    targetInfo = pickle.load(po)

        userData = {}
        userData["targetInfo"] = targetInfo
        userData["targetCallback"] = targetCallback
        userData["callHook"] = callHook
        userData["EmuHelper"] = self
        if hookData is not None:
            userData.update(hookData)
        self.internalRun = False
        self.resetEmuHooks()
        self.h_codehook = self.mu.hook_add(
            UC_HOOK_CODE, self._guided_hook, userData)
        if emuHook is not None:
            self.h_userhook = self.mu.hook_add(UC_HOOK_CODE, emuHook, userData)
        self.h_memhook = self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                                          UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid, userData)
        self.h_inthook = self.mu.hook_add(
            UC_HOOK_INTR, self._hook_interrupt, userData)
        self.blockIdx = 0
        cnt = 1

        # read targets from dict to go from higher to lower addresses
        # this is done to optimize loop by allowing hook to check for and remove other targets visited en route to 
        # current target
        while len(userData["targetInfo"]) > 0:
            userData["targetVA"] = targetVA = sorted(
                userData["targetInfo"].keys(), reverse=True)[0]
            flow, paths = userData["targetInfo"][targetVA]
            funcStart = flow[0][0]
            userData["func_t"] = get_func(funcStart)
            self.pathIdx = 0
            numTargets = len(userData["targetInfo"])
            self.logger.debug("run #%d, %d targets remaining: %s (%d paths)" % (
                cnt, numTargets, self.hexString(targetVA), len(paths)))
            cnt2 = 1
            numPaths = len(paths)
            for path in paths:
                self.logger.debug("emulating path #%d of %d from %s to %s via basic blocks: %s" % (
                    cnt2, numPaths, self.hexString(funcStart), self.hexString(targetVA), repr(path)))
                for reg in self.regs:
                    self.mu.reg_write(self.regs[reg], 0)
                if resetEmuMem:
                    self.reloadBinary()
                self.mu.reg_write(self.regs["sp"], self.stack)
                self.enteredBlock = False
                userData["visitedTargets"] = []
                if preEmuCallback is not None:
                    preEmuCallback(self, self.mu, userData, funcStart)
                if self.arch == UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

                self.mu.emu_start(funcStart, get_func_attr(
                    funcStart, FUNCATTR_END))
                self.pathIdx += 1
                self.blockIdx = 0
                cnt2 += 1
                # remove visited targets during this run from our dict
                for addr in userData["visitedTargets"]:
                    del(userData["targetInfo"][addr])

            cnt += 1

    # simply emulates to the end of whatever bytes are provided
    # these bytes are not loaded into IDB, only emulator memory; IDA APIs are not available for use in hooks here
    def emulateBytes(self, bytes, registerState=None, argv=None, baseAddr=0x400000, emuHook=None, hookData=None):
        if registerState is None:
            registerState = {}
        if argv is None:
            argv = []
        userData = {}
        if hookData is not None:
            userData.update(hookData)
        baseAddr = self.loadBytes(bytes, baseAddr)
        endAddr = baseAddr + len(bytes)
        userData["endAddr"] = endAddr
        mu = self.mu
        self._prepEmuContext(registerState, argv)
        self.resetEmuHooks()
        self.h_codehook = mu.hook_add(
            UC_HOOK_CODE, self._emulateBytes_codehook, userData)
        if emuHook is not None:
            self.h_userhook = mu.hook_add(UC_HOOK_CODE, emuHook, userData)
        self.h_memhook = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                                     UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid, userData)
        self.h_inthook = mu.hook_add(
            UC_HOOK_INTR, self._hook_interrupt, userData)
        mu.emu_start(baseAddr, endAddr)
        return mu

    def hexString(self, va):
        if va > 0xffffffff:
            return "%016X" % va
        else:
            return "%08X" % va

    def pageAlignUp(self, v):
        if v & PAGEALIGNCHECK != 0:
            v += PAGESIZE - (v % PAGESIZE)
        return v

    # returns null-terminated string of bytes from the IDB, starting at addr, do not necessarily need to be printable 
    # characters
    def getIDBString(self, addr):
        buf = ""
        while get_bytes(addr, 1, False) != "\x00" and get_bytes(addr, 1, False) is not None:
            buf += get_bytes(addr, 1, False)
            addr += 1

        return buf

    # determines if the instruction at addr is for returning from a function call
    def isRetInstruction(self, addr):
        if self.safe_print_insn_mnem(addr)[:3].lower() == "ret":
            return True

        if self.safe_print_insn_mnem(addr) in ["BX", "B"] and self.safe_print_operand(addr, 0) == "LR":
            return True

        return False

    # call from an emulation hook to skip the current instruction, moving pc to next instruction
    # useIDA option was added to handle cases where IDA folds multiple instructions
    def skipInstruction(self, userData, useIDA=False):
        if self.arch == UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        if useIDA:
            self.mu.reg_write(self.regs["pc"], next_head(
                userData["currAddr"], get_inf_attr(INF_MAX_EA)))
        else:
            self.mu.reg_write(
                self.regs["pc"], userData["currAddr"] + userData["currAddrSize"])

    # call from an emulation hook to change program counter
    def changeProgramCounter(self, userData, newPC):
        if self.arch == UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        self.mu.reg_write(self.regs["pc"], newPC)

    # retrieves the value of a register, handling subregister addressing
    def getRegVal(self, regName):
        regVal = self.mu.reg_read(self.regs[regName])
        # handle various subregister addressing
        if self.arch == UC_ARCH_X86:
            if regName[:-1] in ["l", "b"]:
                regVal = regVal & 0xFF
            elif regName[:-1] == "h":
                regVal = (regVal & 0xFF00) >> 8
            elif len(regName) == 2 and regName[:-1] == "x":
                regVal = regVal & 0xFFFF
        elif self.arch == UC_ARCH_ARM64:
            if regName[0] == "W":
                regVal = regVal & 0xFFFFFFFF
        return regVal

    def stopEmulation(self, userData):
        self.enteredBlock = False
        if "visitedTargets" in userData and userData["targetVA"] not in userData["visitedTargets"]:
            userData["visitedTargets"].append(
                userData["targetVA"])
        self.mu.emu_stop()

    # checks for null mnem and wraps qstring in tag_remove
    def safe_print_insn_mnem(self, address):
        if print_insn_mnem(address) is None:
            return ""
        return tag_remove(print_insn_mnem(address))

    # checks for null op and wraps qstring in tag_remove
    def safe_print_operand(self, address, opNum):
        if print_operand(address, opNum) is None:
            return ""
        return tag_remove(print_operand(address, opNum))

    def resetEmuHooks(self):
        if self.mu is None:
            self.logger.debug(
                "resetEmuHooks: no hooks to reset, emulator has not been initialized yet")
            return
        if self.h_userhook is not None:
            self.mu.hook_del(self.h_userhook)
            self.h_userhook = None
        if self.h_codehook is not None:
            self.mu.hook_del(self.h_codehook)
            self.h_codehook = None
        if self.h_memhook is not None:
            self.mu.hook_del(self.h_memhook)
            self.h_memhook = None
        if self.h_inthook is not None:
            self.mu.hook_del(self.h_inthook)
            self.h_inthook = None

    # for debugging purposes
    def getEmuState(self):
        if self.arch == UC_ARCH_X86:
            if self.mu._mode == UC_MODE_64:
                out = "RAX: %016X\tRBX: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_RAX), self.mu.reg_read(UC_X86_REG_RBX))
                out += "RCX: %016X\tRDX: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_RCX), self.mu.reg_read(UC_X86_REG_RDX))
                out += "RDI: %016X\tRSI: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_RDI), self.mu.reg_read(UC_X86_REG_RSI))
                out += "R8: %016X\tR9: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_R8), self.mu.reg_read(UC_X86_REG_R9))
                out += "RBP: %016X\tRSP: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_RBP), self.mu.reg_read(UC_X86_REG_RSP))
                out += "RIP: %016X\n" % (self.mu.reg_read(UC_X86_REG_RIP))
            elif self.mu._mode == UC_MODE_32:
                out = "EAX: %016X\tEBX: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_EAX), self.mu.reg_read(UC_X86_REG_EBX))
                out += "ECX: %016X\tEDX: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_ECX), self.mu.reg_read(UC_X86_REG_EDX))
                out += "EDI: %016X\tESI: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_EDI), self.mu.reg_read(UC_X86_REG_ESI))
                out += "EBP: %016X\tESP: %016X\n" % (self.mu.reg_read(
                    UC_X86_REG_EBP), self.mu.reg_read(UC_X86_REG_ESP))
                out += "EIP: %016X\n" % (self.mu.reg_read(UC_X86_REG_EIP))
        elif self.arch == UC_ARCH_ARM64:
            out = "X0: %016X\tX1: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X0), self.mu.reg_read(UC_ARM64_REG_X1))
            out += "X2: %016X\tX3: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X2), self.mu.reg_read(UC_ARM64_REG_X3))
            out += "X4: %016X\tX5: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X4), self.mu.reg_read(UC_ARM64_REG_X5))
            out += "X6: %016X\tX7: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X6), self.mu.reg_read(UC_ARM64_REG_X7))
            out += "X8: %016X\tX9: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X8), self.mu.reg_read(UC_ARM64_REG_X9))
            out += "X10: %016X\tX11: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X10), self.mu.reg_read(UC_ARM64_REG_X11))
            out += "X12: %016X\tX13: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X12), self.mu.reg_read(UC_ARM64_REG_X13))
            out += "X14: %016X\tX15: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X14), self.mu.reg_read(UC_ARM64_REG_X15))
            out += "X16: %016X\tX17: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X16), self.mu.reg_read(UC_ARM64_REG_X17))
            out += "X18: %016X\tX19: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X18), self.mu.reg_read(UC_ARM64_REG_X19))
            out += "X20: %016X\tX21: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X20), self.mu.reg_read(UC_ARM64_REG_X21))
            out += "X22: %016X\tX23: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X22), self.mu.reg_read(UC_ARM64_REG_X23))
            out += "X24: %016X\tX25: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X24), self.mu.reg_read(UC_ARM64_REG_X25))
            out += "X26: %016X\tX27: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X26), self.mu.reg_read(UC_ARM64_REG_X27))
            out += "X28: %016X\tX29: %016X\n" % (self.mu.reg_read(
                UC_ARM64_REG_X28), self.mu.reg_read(UC_ARM64_REG_X29))
            out += "X30: %016X\n" % (self.mu.reg_read(UC_ARM64_REG_X30))
            out += "PC: %016X\n" % (self.mu.reg_read(UC_ARM64_REG_PC))
            out += "SP: %016X\n" % (self.mu.reg_read(UC_ARM64_REG_SP))
        elif self.arch == UC_ARCH_ARM:
            out = "R0: %08X\tR1: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R0), self.mu.reg_read(UC_ARM_REG_R1))
            out += "R2: %08X\tR3: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R2), self.mu.reg_read(UC_ARM_REG_R3))
            out += "R4: %08X\tR5: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R4), self.mu.reg_read(UC_ARM_REG_R5))
            out += "R6: %08X\tR7: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R6), self.mu.reg_read(UC_ARM_REG_R7))
            out += "R8: %08X\tR9: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R8), self.mu.reg_read(UC_ARM_REG_R9))
            out += "R10: %08X\tR11: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R10), self.mu.reg_read(UC_ARM_REG_R11))
            out += "R12: %08X\tR13: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R12), self.mu.reg_read(UC_ARM_REG_R13))
            out += "R14: %08X\tR15: %08X\n" % (self.mu.reg_read(
                UC_ARM_REG_R14), self.mu.reg_read(UC_ARM_REG_R15))
            out += "PC: %08X\n" % self.mu.reg_read(UC_ARM_REG_R15)
            out += "SP: %08X\n" % self.mu.reg_read(UC_ARM_REG_R13)
        else:
            return ""
        return out

    # returns null-terminated string of bytes from the emulator's memory, starting at addr, do not necessarily need 
    # to be printable characters
    def getEmuString(self, addr):
        out = ""
        while str(self.mu.mem_read(addr, 1)) != "\x00":
            out += str(self.mu.mem_read(addr, 1))
            addr += 1
        return out

    # reads pointer value in emulator's memory
    def getEmuPtr(self, va):
        return struct.unpack(self.pack_fmt, self.mu.mem_read(va, self.size_pointer))[0]

    # helper func to save user from having to access mu directly
    def getEmuBytes(self, addr, n_bytes):
        assert type(addr) == types.LongType
        assert type(n_bytes) == types.IntType

        for r_start, r_end, r_perm in self.mu.mem_regions():
            self.logger.debug("getEmuBytes - mem_region: {0}:{1}".format(hex(r_start), hex(r_end)))
            if r_start <= addr <= r_end:
                if(r_end - r_start + 1 >= n_bytes):        
                    return self.mu.mem_read(addr, n_bytes)
                else:
                    self.logger.warning("getEmuBytes - n_bytes too large")
                    return None
        self.logger.debug("getEmuBytes - addr not found in any regions")
        return None

    # for debugging
    def format_bb(self, bb):
        bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
                  4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
        return("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
               "Type: %s" % (bb.id, bb.start_ea, bb.end_ea, idc.prev_head(bb.end_ea, get_inf_attr(INF_MIN_EA)),
                             (bb.end_ea - bb.start_ea), bbtype[bb.type]))

    def getSegSize(self, ea, segEnd):
        size = 0
        while has_value(get_full_flags(ea)):
            if ea >= segEnd:
                break
            size += 1
            ea += 1
        return size

    # returns True if ea is in an area designated by IDA to be in thumb mode
    def isThumbMode(self, ea):
        return get_sreg(ea, 20) == 1

    def pageAlign(self, addr):
        return addr & 0xfffffffffffff000

    # uses depth first searching on IDA's FlowChart in a given target's function to find up to maxPaths possible 
    # ways to target from function start
    # this will return an empty list if there are no branches in function
    # returns IDA's FlowChart object, converted to a Python list of tuples, as well as a list of lists containing 
    # paths to targets in the form of basic block IDs
    def getPaths(self, targetVA, maxPaths):
        function = get_func(targetVA)
        flowchart = FlowChart(function)
        target_bb = self.getBlockIdByVA(targetVA, flowchart)
        if function.start_ea in self.paths:
            paths = self.paths[function.start_ea]
        else:
            start_bb = self.get_start_bb(function, flowchart)
            self.logger.debug("exploring function with %d blocks" % flowchart.size)
            self._explore(start_bb)
            self.explorePaths.pop()
            paths = deepcopy(self.explorePaths)
            del(self.explorePaths)
            self.paths[function.start_ea] = paths
        targetPaths = []
        for p in paths:
            if target_bb in p:
                targetPaths.append(p)

        # truncate paths to target bb
        for i in range(len(targetPaths)):
            targetPaths[i] = targetPaths[i][:targetPaths[i].index(
                target_bb) + 1]

        # unique list of paths
        uniqTargetPaths = []
        for p in targetPaths:
            if p not in uniqTargetPaths:
                uniqTargetPaths.append(p)
        uniqTargetPaths = uniqTargetPaths[:maxPaths]
        self.logger.debug("code paths to target: %s" % repr(uniqTargetPaths))

        # create my own flowchart object so it can be pickled for debugging purposes
        flow = {}
        for bb in flowchart:
            flow[bb.id] = (bb.start_ea, bb.end_ea)
        return flow, uniqTargetPaths

    # same as getPaths, but only get first path to target found during exploration
    def getPath(self, targetVA):
        function = get_func(targetVA)
        flowchart = FlowChart(function)
        target_bb = self.getBlockIdByVA(targetVA, flowchart)
        start_bb = self.get_start_bb(function, flowchart)
        if DEBUG > 0:
            self.logger.debug("exploring function with %d blocks" % flowchart.size)
        idx = self._explore(start_bb, target_bb)
        if idx is None:
            self.logger.debug(
                "path to target %s could not be found, skipping" % self.hexString(targetVA))
            return None, None

        path = deepcopy(self.explorePaths[idx])
        del(self.explorePaths)
        if DEBUG > 0:
            self.logger.debug("code path to target: %s" % repr(path))

        # create my own flowchart object so it can be pickled for debugging purposes
        flow = {}
        for bb in flowchart:
            flow[bb.id] = (bb.start_ea, bb.end_ea)
        return flow, [path]

    def get_start_bb(self, function, flowchart):
        for bb in flowchart:
            if bb.start_ea == function.start_ea:
                return bb

    def getBlockIdByVA(self, targetVA, flowchart):
        return self.getBlockByVA(targetVA, flowchart).id

    def getBlockByVA(self, targetVA, flowchart):
        for bb in flowchart:
            if targetVA >= bb.start_ea and targetVA < bb.end_ea:
                return bb

    def isTerminatingBB(self, bb):
        if bb.type == fcb_ret or bb.type == fcb_noret or (bb.type == fcb_indjump and len(list(bb.succs())) == 0):
            return True
        for b in bb.succs():
            if b.type == fcb_extern:
                return True

        return False

    # sets up arch/mode specific variables, initializes emulator
    def initEmuHelper(self):
        info = get_inf_structure()
        if tag_remove(info.procName) == "metapc":
            self.arch = UC_ARCH_X86
            arch = "X86"
            if info.is_64bit():
                self.mode = UC_MODE_64
                self.derefPtr = get_qword
                mode = "64-bit"
                self.size_pointer = 8
                self.pack_fmt = "<Q"
                self.pageMask = 0xfffffffffffff000
                self.regs = {"ax": UC_X86_REG_RAX, "bx": UC_X86_REG_RBX, "cx": UC_X86_REG_RCX, "dx": UC_X86_REG_RDX, 
                    "di": UC_X86_REG_RDI, "si": UC_X86_REG_RSI, "bp": UC_X86_REG_RBP, "sp": UC_X86_REG_RSP, "ip": 
                    UC_X86_REG_RIP, "pc": UC_X86_REG_RIP, "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": 
                    UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX, "rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI, "rbp": 
                    UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP, "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "r10": 
                    UC_X86_REG_R10, "r11": UC_X86_REG_R11, "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13, "r14": 
                    UC_X86_REG_R14, "r15": UC_X86_REG_R15, "ret": UC_X86_REG_RAX}
                if info.filetype == 11:
                    self.filetype = "PE"
                    self.tilName = "mssdk_win7"
                    self.regs.update({"arg1": UC_X86_REG_RCX, "arg2": UC_X86_REG_RDX,
                                      "arg3": UC_X86_REG_R8, "arg4": UC_X86_REG_R9})
                elif info.filetype == 25:
                    self.filetype = "MACHO"
                    self.tilName = "macosx64"
                    self.regs.update({"arg1": UC_X86_REG_RDI, "arg2": UC_X86_REG_RSI,
                                      "arg3": UC_X86_REG_RDX, "arg4": UC_X86_REG_RCX})
                elif info.filetype == 18:
                    self.filetype = "ELF"
                    self.tilName = "gnulnx_x64"
                    self.regs.update({"arg1": UC_X86_REG_RDI, "arg2": UC_X86_REG_RSI,
                                      "arg3": UC_X86_REG_RDX, "arg4": UC_X86_REG_RCX})
                else:
                    self.filetype = "UNKNOWN"
                    # assume PE for mem dumps
                    self.regs.update({"arg1": UC_X86_REG_RCX, "arg2": UC_X86_REG_RDX,
                                      "arg3": UC_X86_REG_R8, "arg4": UC_X86_REG_R9})
            elif info.is_32bit():
                if info.filetype == 11:
                    self.filetype = "PE"
                    self.tilName = "mssdk"
                elif info.filetype == 25:
                    self.filetype = "MACHO"
                    self.tilName = "macosx"
                elif info.filetype == 18:
                    self.filetype = "ELF"
                    self.tilName = "gnulnx_x86"
                else:
                    self.filetype = "UNKNOWN"
                self.mode = UC_MODE_32
                self.derefPtr = get_wide_dword
                mode = "32-bit"
                self.size_pointer = 4
                self.pack_fmt = "<I"
                self.pageMask = 0xfffff000
                self.regs = {"ax": UC_X86_REG_EAX, "bx": UC_X86_REG_EBX, "cx": UC_X86_REG_ECX, "dx": UC_X86_REG_EDX, 
                    "di": UC_X86_REG_EDI, "si": UC_X86_REG_ESI, "bp": UC_X86_REG_EBP, "sp": UC_X86_REG_ESP, "ip": 
                    UC_X86_REG_EIP, "pc": UC_X86_REG_EIP, "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": 
                    UC_X86_REG_ECX, "edx": UC_X86_REG_EDX, "edi": UC_X86_REG_EDI, "esi": UC_X86_REG_ESI, "ebp": 
                    UC_X86_REG_EBP, "esp": UC_X86_REG_ESP, "ret": UC_X86_REG_EAX}
            else:
                self.logger.debug(
                    "sample contains code for unsupported processor architecture")
                return
        elif tag_remove(info.procName) == "ARM":
            self.mode = UC_MODE_ARM
            mode = "ARM"
            if info.is_64bit():
                self.arch = UC_ARCH_ARM64
                arch = "ARM64"
                if info.filetype == 11:
                    self.filetype = "PE"
                    self.tilName = "mssdk_win7"
                elif info.filetype == 25:
                    self.filetype = "MACHO"
                    self.tilName = "macosx64"
                elif info.filetype == 18:
                    self.filetype = "ELF"
                    self.tilName = "gnulnx_x64"
                else:
                    self.filetype = "UNKNOWN"
                self.size_pointer = 8
                self.pack_fmt = "<Q"
                self.derefPtr = get_qword
                self.pageMask = 0xfffffffffffff000
                self.regs = {"R0": UC_ARM64_REG_X0, "R1": UC_ARM64_REG_X1, "R2": UC_ARM64_REG_X2, "R3": 
                    UC_ARM64_REG_X3, "R4": UC_ARM64_REG_X4, "R5": UC_ARM64_REG_X5, "R6": UC_ARM64_REG_X6, "R7": 
                    UC_ARM64_REG_X7, "R8": UC_ARM64_REG_X8, "R9": UC_ARM64_REG_X9, "R10": UC_ARM64_REG_X10, "R11": 
                    UC_ARM64_REG_X11, "R12": UC_ARM64_REG_X12, "R13": UC_ARM64_REG_X13, "R14": UC_ARM64_REG_X14, 
                    "R15": UC_ARM64_REG_X15, "X0": UC_ARM64_REG_X0, "X1": UC_ARM64_REG_X1, "X2": UC_ARM64_REG_X2, 
                    "X3": UC_ARM64_REG_X3, "X4": UC_ARM64_REG_X4, "X5": UC_ARM64_REG_X5, "X6": UC_ARM64_REG_X6, "X7": 
                    UC_ARM64_REG_X7, "X8": UC_ARM64_REG_X8, "X9": UC_ARM64_REG_X9, "X10": UC_ARM64_REG_X10, "X11": 
                    UC_ARM64_REG_X11, "X12": UC_ARM64_REG_X12, "X13": UC_ARM64_REG_X13, "X14": UC_ARM64_REG_X14, 
                    "X15": UC_ARM64_REG_X15, "X16": UC_ARM64_REG_X16, "X17": UC_ARM64_REG_X17, "X18": UC_ARM64_REG_X18
                    , "X19": UC_ARM64_REG_X19, "X20": UC_ARM64_REG_X20, "X21": UC_ARM64_REG_X21, "X22": 
                    UC_ARM64_REG_X22, "X23": UC_ARM64_REG_X23, "X24": UC_ARM64_REG_X24, "X25": UC_ARM64_REG_X25, 
                    "X26": UC_ARM64_REG_X26, "X27": UC_ARM64_REG_X27, "X28": UC_ARM64_REG_X28, "X29": UC_ARM64_REG_X29
                    , "X30": UC_ARM64_REG_X30, "W0": UC_ARM64_REG_X0, "W1": UC_ARM64_REG_X1, "W2": UC_ARM64_REG_X2, 
                    "W3": UC_ARM64_REG_X3, "W4": UC_ARM64_REG_X4, "W5": UC_ARM64_REG_X5, "W6": UC_ARM64_REG_X6, "W7": 
                    UC_ARM64_REG_X7, "W8": UC_ARM64_REG_X8, "W9": UC_ARM64_REG_X9, "W10": UC_ARM64_REG_X10, "W11": 
                    UC_ARM64_REG_X11, "W12": UC_ARM64_REG_X12, "W13": UC_ARM64_REG_X13, "W14": UC_ARM64_REG_X14, 
                    "W15": UC_ARM64_REG_X15, "W16": UC_ARM64_REG_X16, "W17": UC_ARM64_REG_X17, "W18": UC_ARM64_REG_X18
                    , "W19": UC_ARM64_REG_X19, "W20": UC_ARM64_REG_X20, "W21": UC_ARM64_REG_X21, "W22": 
                    UC_ARM64_REG_X22, "W23": UC_ARM64_REG_X23, "W24": UC_ARM64_REG_X24, "W25": UC_ARM64_REG_X25, 
                    "W26": UC_ARM64_REG_X26, "W27": UC_ARM64_REG_X27, "W28": UC_ARM64_REG_X28, "W29": UC_ARM64_REG_X29
                    , "W30": UC_ARM64_REG_X30, "PC": UC_ARM64_REG_PC, "pc": UC_ARM64_REG_PC, "LR": UC_ARM64_REG_X30, 
                    "SP": UC_ARM64_REG_SP, "sp": UC_ARM64_REG_SP, "ret": UC_ARM64_REG_X0, "S0": UC_ARM64_REG_S0, 
                    "S1": UC_ARM64_REG_S1, "S2": UC_ARM64_REG_S2, "S3": UC_ARM64_REG_S3, "S4": UC_ARM64_REG_S4, "S5": 
                    UC_ARM64_REG_S5, "S6": UC_ARM64_REG_S6, "S7": UC_ARM64_REG_S7, "S8": UC_ARM64_REG_S8, "S9": 
                    UC_ARM64_REG_S9, "S10": UC_ARM64_REG_S10, "S11": UC_ARM64_REG_S11, "S12": UC_ARM64_REG_S12, "S13":
                    UC_ARM64_REG_S13, "S14": UC_ARM64_REG_S14, "S15": UC_ARM64_REG_S15, "S16": UC_ARM64_REG_S16, 
                    "S17": UC_ARM64_REG_S17, "S18": UC_ARM64_REG_S18, "S19": UC_ARM64_REG_S19, "S20": UC_ARM64_REG_S20
                    , "S21": UC_ARM64_REG_S21, "S22": UC_ARM64_REG_S22, "S23": UC_ARM64_REG_S23, "S24": 
                    UC_ARM64_REG_S24, "S25": UC_ARM64_REG_S25, "S26": UC_ARM64_REG_S26, "S27": UC_ARM64_REG_S27, 
                    "S28": UC_ARM64_REG_S28, "S29": UC_ARM64_REG_S29, "S30": UC_ARM64_REG_S30, "S31": UC_ARM64_REG_S31
                    , "D0": UC_ARM64_REG_D0, "D1": UC_ARM64_REG_D1, "D2": UC_ARM64_REG_D2, "D3": UC_ARM64_REG_D3, 
                    "D4": UC_ARM64_REG_D4, "D5": UC_ARM64_REG_D5, "D6": UC_ARM64_REG_D6, "D7": UC_ARM64_REG_D7, "D8": 
                    UC_ARM64_REG_D8, "D9": UC_ARM64_REG_D9, "D10": UC_ARM64_REG_D10, "D11": UC_ARM64_REG_D11, "D12": 
                    UC_ARM64_REG_D12, "D13": UC_ARM64_REG_D13, "D14": UC_ARM64_REG_D14, "D15": UC_ARM64_REG_D15, 
                    "D16": UC_ARM64_REG_D16, "D17": UC_ARM64_REG_D17, "D18": UC_ARM64_REG_D18, "D19": UC_ARM64_REG_D19
                    , "D20": UC_ARM64_REG_D20, "D21": UC_ARM64_REG_D21, "D22": UC_ARM64_REG_D22, "D23": 
                    UC_ARM64_REG_D23, "D24": UC_ARM64_REG_D24, "D25": UC_ARM64_REG_D25, "D26": UC_ARM64_REG_D26, 
                    "D27": UC_ARM64_REG_D27, "D28": UC_ARM64_REG_D28, "D29": UC_ARM64_REG_D29, "D30": UC_ARM64_REG_D30
                    , "D31": UC_ARM64_REG_D31, "H0": UC_ARM64_REG_H0, "H1": UC_ARM64_REG_H1, "H2": UC_ARM64_REG_H2, 
                    "H3": UC_ARM64_REG_H3, "H4": UC_ARM64_REG_H4, "H5": UC_ARM64_REG_H5, "H6": UC_ARM64_REG_H6, "H7": 
                    UC_ARM64_REG_H7, "H8": UC_ARM64_REG_H8, "H9": UC_ARM64_REG_H9, "H10": UC_ARM64_REG_H10, "H11": 
                    UC_ARM64_REG_H11, "H12": UC_ARM64_REG_H12, "H13": UC_ARM64_REG_H13, "H14": UC_ARM64_REG_H14, 
                    "H15": UC_ARM64_REG_H15, "H16": UC_ARM64_REG_H16, "H17": UC_ARM64_REG_H17, "H18": UC_ARM64_REG_H18
                    , "H19": UC_ARM64_REG_H19, "H20": UC_ARM64_REG_H20, "H21": UC_ARM64_REG_H21, "H22": 
                    UC_ARM64_REG_H22, "H23": UC_ARM64_REG_H23, "H24": UC_ARM64_REG_H24, "H25": UC_ARM64_REG_H25, 
                    "H26": UC_ARM64_REG_H26, "H27": UC_ARM64_REG_H27, "H28": UC_ARM64_REG_H28, "H29": UC_ARM64_REG_H29
                    , "H30": UC_ARM64_REG_H30, "H31": UC_ARM64_REG_H31, "Q0": UC_ARM64_REG_Q0, "Q1": UC_ARM64_REG_Q1, 
                    "Q2": UC_ARM64_REG_Q2, "Q3": UC_ARM64_REG_Q3, "Q4": UC_ARM64_REG_Q4, "Q5": UC_ARM64_REG_Q5, "Q6": 
                    UC_ARM64_REG_Q6, "Q7": UC_ARM64_REG_Q7, "Q8": UC_ARM64_REG_Q8, "Q9": UC_ARM64_REG_Q9, "Q10": 
                    UC_ARM64_REG_Q10, "Q11": UC_ARM64_REG_Q11, "Q12": UC_ARM64_REG_Q12, "Q13": UC_ARM64_REG_Q13, 
                    "Q14": UC_ARM64_REG_Q14, "Q15": UC_ARM64_REG_Q15, "Q16": UC_ARM64_REG_Q16, "Q17": UC_ARM64_REG_Q17
                    , "Q18": UC_ARM64_REG_Q18, "Q19": UC_ARM64_REG_Q19, "Q20": UC_ARM64_REG_Q20, "Q21": 
                    UC_ARM64_REG_Q21, "Q22": UC_ARM64_REG_Q22, "Q23": UC_ARM64_REG_Q23, "Q24": UC_ARM64_REG_Q24, 
                    "Q25": UC_ARM64_REG_Q25, "Q26": UC_ARM64_REG_Q26, "Q27": UC_ARM64_REG_Q27, "Q28": UC_ARM64_REG_Q28
                    , "Q29": UC_ARM64_REG_Q29, "Q30": UC_ARM64_REG_Q30, "Q31": UC_ARM64_REG_Q31}
                self.regs.update({"arg1": UC_ARM64_REG_X0, "arg2": UC_ARM64_REG_X1,
                                  "arg3": UC_ARM64_REG_X2, "arg4": UC_ARM64_REG_X3})
            elif info.is_32bit():
                self.arch = UC_ARCH_ARM
                arch = "ARM"
                if info.filetype == 11:
                    self.filetype = "PE"
                    self.tilName = "mssdk"
                elif info.filetype == 25:
                    self.filetype = "MACHO"
                    self.tilName = "macosx"
                elif info.filetype == 18:
                    self.filetype = "ELF"
                    self.tilName = "gnulnx_x86"
                else:
                    self.filetype = "UNKNOWN"
                self.size_pointer = 4
                self.pack_fmt = "<I"
                self.derefPtr = get_wide_dword
                self.pageMask = 0xfffff000
                self.regs = {"R0": UC_ARM_REG_R0, "R1": UC_ARM_REG_R1, "R2": UC_ARM_REG_R2, "R3": UC_ARM_REG_R3, "R4":
                    UC_ARM_REG_R4, "R5": UC_ARM_REG_R5, "R6": UC_ARM_REG_R6, "R7": UC_ARM_REG_R7, "R8": UC_ARM_REG_R8,
                    "R9": UC_ARM_REG_R9, "R10": UC_ARM_REG_R10, "R11": UC_ARM_REG_R11, "R12": UC_ARM_REG_R12, "R13": 
                    UC_ARM_REG_R13, "R14": UC_ARM_REG_R14, "R15": UC_ARM_REG_R15, "PC": UC_ARM_REG_R15, "pc": 
                    UC_ARM_REG_R15, "LR": UC_ARM_REG_R14, "SP": UC_ARM_REG_R13, "sp": UC_ARM_REG_R13, "apsr": 
                    UC_ARM_REG_APSR, "APSR": UC_ARM_REG_APSR, "ret": UC_ARM_REG_R0, "S0": UC_ARM_REG_S0, "S1": 
                    UC_ARM_REG_S1, "S2": UC_ARM_REG_S2, "S3": UC_ARM_REG_S3, "S4": UC_ARM_REG_S4, "S5": UC_ARM_REG_S5,
                    "S6": UC_ARM_REG_S6, "S7": UC_ARM_REG_S7, "S8": UC_ARM_REG_S8, "S9": UC_ARM_REG_S9, "S10": 
                    UC_ARM_REG_S10, "S11": UC_ARM_REG_S11, "S12": UC_ARM_REG_S12, "S13": UC_ARM_REG_S13, "S14": 
                    UC_ARM_REG_S14, "S15": UC_ARM_REG_S15, "S16": UC_ARM_REG_S16, "S17": UC_ARM_REG_S17, "S18": 
                    UC_ARM_REG_S18, "S19": UC_ARM_REG_S19, "S20": UC_ARM_REG_S20, "S21": UC_ARM_REG_S21, "S22": 
                    UC_ARM_REG_S22, "S23": UC_ARM_REG_S23, "S24": UC_ARM_REG_S24, "S25": UC_ARM_REG_S25, "S26": 
                    UC_ARM_REG_S26, "S27": UC_ARM_REG_S27, "S28": UC_ARM_REG_S28, "S29": UC_ARM_REG_S29, "S30": 
                    UC_ARM_REG_S30, "S31": UC_ARM_REG_S31}
                self.regs.update({"arg1": UC_ARM_REG_R0, "arg2": UC_ARM_REG_R1,
                                  "arg3": UC_ARM_REG_R2, "arg4": UC_ARM_REG_R3})
            else:
                self.logger.debug(
                    "sample contains code for unsupported processor architecture")
                return
        else:
            self.logger.debug(
                "sample contains code for unsupported processor architecture")
            return

        # Initialize emulator
        mu = Uc(self.arch, self.mode)
        self.logger.debug("initialized emulator for %s with %s architecture in %s mode" % (
            self.filetype, arch, mode))
        self.mu = mu
        if self.arch == UC_ARCH_ARM or self.arch == UC_ARCH_ARM64:
            self._enableVFP()

    # unmap all emulator memory
    def resetEmulatorMemory(self):
        for region in self.mu.mem_regions():
            self.mu.mem_unmap(region[0], region[1] - region[0] + 1)

    def resetEmulatorHeapAndStack(self):
        for region in self.mu.mem_regions():
            if region[0] != self.baseAddr:
                self.mu.mem_unmap(region[0], region[1] - region[0] + 1)
                self.logger.debug("unmapped %s to %s" % (
                    self.hexString(region[0]), self.hexString(region[1])))
        self._buildStack()

    # reset emulator memory and rewrite binary segments to emulator memory, build new stack
    def reloadBinary(self):
        self.resetEmulatorMemory()
        baseAddr = get_inf_attr(INF_MIN_EA)
        endAddr = get_inf_attr(INF_MAX_EA)
        self.baseAddr = baseAddr
        memsize = endAddr - baseAddr
        memsize = self.pageAlignUp(memsize)
        # map all binary segments as one memory region for easier management
        self.mu.mem_map(baseAddr & self.pageMask, memsize)
        for segVA in Segments():
            segName = get_segm_name(segVA)
            endVA = get_segm_end(segVA)
            segSizeTotal = endVA - segVA
            segSize = self.getSegSize(segVA, endVA)
            self.logger.debug("bytes in seg: %s" % self.hexString(segSize))
            self.logger.debug("mapping segment %s: %s - %s" %
                          (segName, self.hexString(segVA), self.hexString(endVA)))
            if segSize > 0:
                segBytes = get_bytes(segVA, segSize, False)
                self.mu.mem_write(segVA, segBytes)
            segLeftover = segSizeTotal - segSize
            if segLeftover > 0:
                self.mu.mem_write(segVA + segSize, "\x00" * segLeftover)

        self._buildStack()

    # allocs mem and writes bytes into it
    def loadBytes(self, bytes, addr=None):
        mem = self.allocEmuMem(len(bytes), addr)
        self.mu.mem_write(mem, bytes)
        return mem

    # allocate emulator memory, attempts to honor specified address, otherwise begins allocations at the next page 
    # aligned address above the highest, returns address, rebased if necessary
    def allocEmuMem(self, size, addr=None):
        allocSize = self.pageAlignUp(size)
        if addr is None:
            baseAddr = addr = self._findValidMemAddress()
        else:
            isValid = True
            baseAddr = self.pageAlign(addr)
            offs = addr - baseAddr
            for region in self.mu.mem_regions():
                # if start or end of region falls in range of a previous region
                if (baseAddr >= region[0] and baseAddr < region[1]) or (baseAddr + allocSize >= region[0] and 
                    baseAddr + allocSize < region[1]):
                    isValid = False
                    break
                # if region completely envelopes a previous region
                if baseAddr < region[0] and baseAddr + allocSize > region[1]:
                    isValid = False
                    break
            if isValid == False:
                baseAddr = self._findValidMemAddress()
                addr = baseAddr + offs
        self.logger.debug("mapping %s bytes @%s" %
                      (self.hexString(allocSize), self.hexString(baseAddr)))
        self.mu.mem_map(baseAddr, allocSize)
        return addr

    # maps null memory as requested during emulation
    def _hook_mem_invalid(self, mu, access, address, size, value, user_data):
        self.logger.debug("invalid memory operation for %s" %
                      self.hexString(address))
        try:
            mu.mem_map(address & self.pageMask, PAGESIZE)
            mu.mem_write(address & self.pageMask, "\x00" * PAGESIZE)
        except:
            self.logger.debug("error writing to %s, changing IP from %s to %s" % (self.hexString(address), self.hexString(
                userData['currAddr']), self.hexString(userData['currAddr'] + userData['currAddrSize'])))
            mu.reg_write(
                self.regs["pc"], userData['currAddr'] + userData['currAddrSize'])
        return True

    # cannot seem to move IP forward from this hook for some reason..
    # patches current instruction with NOPs
    def _hook_interrupt(self, mu, intno, userData):
        self.logger.debug("interrupt #%d received" % (intno))
        if self.arch == UC_ARCH_X86:
            mu.mem_write(userData["currAddr"], "\x90" *
                         userData["currAddrSize"])
        elif self.arch == UC_ARCH_ARM:
            if self.mode == UC_MODE_THUMB:
                mu.mem_write(userData["currAddr"],
                             "\x00\xbf" * (userData["currAddrSize"] / 2))
            else:
                mu.mem_write(
                    userData["currAddr"], "\x00\xf0\x20\xe3" * (userData["currAddrSize"] / 4))
        elif self.arch == UC_ARCH_ARM64:
            mu.mem_write(
                userData["currAddr"], "\x1f\x20\x03\xd5" * (userData["currAddrSize"] / 4))
        self.enteredBlock = False
        return True

    # instruction hook used by emulateRange function
    # implements bare bones instrumentation to handle basic code flow
    def _emulateRange_codehook(self, uc, address, size, userData):
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            if self.arch == UC_ARCH_ARM and userData["changeThumbMode"]:
                self._handleThumbMode(address)
                userData["changeThumbMode"] = False
                return

            if DEBUG > 0:
                if DEBUG > 1:
                    self.logger.debug(self.getEmuState(uc))
                dis = tag_remove(generate_disasm_line(address, 0))
                self.logger.debug("%s: %s" % (self.hexString(address), dis))

            # stop emulation if specified endAddr is reached
            if userData["endAddr"] is not None:
                if address == userData["endAddr"]:
                    self.stopEmulation(userData)
                    return
            if self._isBadBranch(userData):
                self.skipInstruction(userData)
                return
            # stop annoying run ons if we end up somewhere we dont belong
            if str(self.mu.mem_read(address, size)) == "\x00" * size:
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                self.stopEmulation(userData)
                return

            # otherwise, stop emulation when returning from function emulation began in
            elif self.isRetInstruction(address) and get_func_attr(address, FUNCATTR_START) == userData["funcStart"]:
                self.stopEmulation(userData)
                return
            elif self.isRetInstruction(address) and self.arch == UC_ARCH_ARM:
                # check mode of return address if ARM
                retAddr = self.getEmuPtr(self.getRegVal("LR"))
                if self.isThumbMode(retAddr):
                    userData["changeThumbMode"] = True

            if self.safe_print_insn_mnem(address) in self.callMnems or (self.safe_print_insn_mnem(address) == "B" and 
                get_name_ea_simple(self.safe_print_operand(address, 0)) == get_func_attr(get_name_ea_simple(
                self.safe_print_operand(address, 0)), FUNCATTR_START)):
                if userData["callHook"] is not None:
                    userData["callHook"](uc, address, size, userData)

                # skip calls if specified or there are no instructions to emulate at destination address
                if userData["skipCalls"] == True or (get_operand_type(address, 0) == 7 and str(uc.mem_read(
                    get_operand_value(address, 0), self.size_pointer)) == "\x00" * self.size_pointer):
                    self.skipInstruction(userData)
                    # get IDA's SP delta value for next instruction to adjust stack accordingly since we are skipping 
                    # this instruction
                    uc.reg_write(self.regs["sp"], self.getRegVal(
                        "sp") + get_sp_delta(userData["func_t"], address + size))

                if self.arch == UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

        except Exception, err:
            self.logger.debug("exception in emulateRange_codehook: %s" % str(err))
            print("exception in emulateRange_codehook: %s" % str(err))
            self.stopEmulation(userData)

    # instruction hook used by emulateBytes function
    # implements bare bones instrumentation to handle basic code flow
    def _emulateBytes_codehook(self, uc, address, size, userData):
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            # stop emulation if specified endAddr is reached
            if userData["endAddr"] is not None:
                if address == userData["endAddr"]:
                    self.stopEmulation(userData)
                    return
                    
            # stop annoying run ons if we end up somewhere we dont belong
            if str(self.mu.mem_read(address, 0x10)) == "\x00" * 0x10:
                self.stopEmulation(userData)
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                return

        except Exception, err:
            self.logger.debug("exception in emulateBytes_codehook: %s" % str(err))
            print("exception in emulateBytes_codehook: %s" % str(err))
            self.stopEmulation(userData)

    # this instruction hook is used by the iterate feature, forces execution down a specified path
    def _guided_hook(self, uc, address, size, userData):
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            if self.arch == UC_ARCH_ARM and userData["changeThumbMode"]:
                self._handleThumbMode(address)
                userData["changeThumbMode"] = False
                return
            if DEBUG > 0:
                if DEBUG > 1:
                    self.logger.debug(self.getEmuState(uc))
                dis = tag_remove(generate_disasm_line(address, 0))
                self.logger.debug("%s: %s" % (self.hexString(address), dis))
            if self.arch == UC_ARCH_ARM:
                # since there are lots of bad branches during emulation and we are forcing it anyways
                if self.safe_print_insn_mnem(address)[:3] in ["TBB", "TBH"]:
                    # skip over interleaved jump table
                    nextInsnAddr = self._scanForCode(address + size)
                    self.changeProgramCounter(userData, nextInsnAddr)
                    return
            elif self._isBadBranch(userData):
                self.skipInstruction(userData)
                return
            
            flow, paths = userData["targetInfo"][userData["targetVA"]]
            # check if we are out of our block bounds or re-entering our block in a loop
            bbEnd = prev_head(
                flow[paths[self.pathIdx][self.blockIdx]][1], get_inf_attr(INF_MIN_EA))
            bbStart = flow[paths[self.pathIdx][self.blockIdx]][0]
            if address == bbStart and self.enteredBlock == True:
                if self.blockIdx < len(paths[self.pathIdx]) - 1:
                    self.logger.debug("loop re-entering block #%d (%s -> %s), forcing PC to %s" % (self.blockIdx, 
                        self.hexString(
                        bbStart), self.hexString(bbEnd), self.hexString(
                            flow[paths[self.pathIdx][self.blockIdx + 1]][0])))
                    # force PC to follow paths
                    uc.reg_write(
                        self.regs["pc"], flow[paths[self.pathIdx][self.blockIdx + 1]][0])
                    self.blockIdx += 1
                    self.enteredBlock = False
                    if self.arch == UC_ARCH_ARM:
                        userData["changeThumbMode"] = True
                    return
                else:
                    self.logger.debug(
                        "loop re-entering block #%d (%s -> %s), but no more blocks! bailing out of this function.." % 
                        (self.blockIdx, self.hexString(bbStart), self.hexString(bbEnd)))
                    self.stopEmulation(userData)
                    return
            elif (address > bbEnd or address < bbStart):
                # check if we skipped over our target (our next block index is out of range), this can happen in ARM 
                # with conditional instructions
                if self.blockIdx + 1 >= len(paths[self.pathIdx]):
                    self.logger.debug(
                        "we missed our target! bailing out of this function..")
                    self.stopEmulation(userData)
                    return
                self.logger.debug("%s is outside of block #%d (%s -> %s), forcing PC to %s" % (self.hexString(address), 
                    self.blockIdx, self.hexString(bbStart), self.hexString(bbEnd), self.hexString(
                    flow[paths[self.pathIdx][self.blockIdx + 1]][0])))
                # force PC to follow paths
                uc.reg_write(
                    self.regs["pc"], flow[paths[self.pathIdx][self.blockIdx + 1]][0])
                self.blockIdx += 1
                self.enteredBlock = False
                if self.arch == UC_ARCH_ARM:
                    userData["changeThumbMode"] = True
                return

            if address == bbStart:
                self.enteredBlock = True
            # possibly a folded instruction or invalid instruction
            if self.safe_print_insn_mnem(address) == "":
                if self.safe_print_insn_mnem(address + size) == "":
                    if self.safe_print_insn_mnem(address + size * 2) == "":
                        self.logger.debug(
                            "invalid instruction encountered @%s, bailing.." % self.hexString(address))
                        self.stopEmulation(userData)
                    return
                return

            # stop annoying run ons if we end up somewhere we dont belong
            if str(self.mu.mem_read(address, 0x10)) == "\x00" * 0x10:
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                self.stopEmulation(userData)
                return
                
            # this is our stop, this is where we trigger user-defined callback with our info
            if address == userData["targetVA"]:
                self.logger.debug("target %s hit" %
                              self.hexString(userData["targetVA"]))
                self._targetHit(uc, address, userData)
                self.stopEmulation(userData)
            elif address in userData["targetInfo"]:
                # this address is another target in the dict, process it and continue onward
                self.logger.debug("target %s found on the way to %s" % (
                    self.hexString(address), self.hexString(userData["targetVA"])))
                self._targetHit(uc, address, userData)

            if self.safe_print_insn_mnem(address) in self.callMnems or (self.safe_print_insn_mnem(address) == "B" and 
                get_name_ea_simple(self.safe_print_operand(address, 0)) == get_func_attr(get_name_ea_simple(
                self.safe_print_operand(address, 0)), FUNCATTR_START)):
                if userData["callHook"] is not None:
                    userData["callHook"](uc, address, size, userData)

                # get IDA's SP delta value for next instruction to adjust stack accordingly since we are skipping this
                # instruction
                uc.reg_write(self.regs["sp"], self.getRegVal(
                    "sp") + get_sp_delta(userData["func_t"], address + size))
                if self.arch == UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

                # if the pc has been changed by the hook, don't skip instruction and undo the change
                if self.getRegVal("pc") != userData["currAddr"]:
                    return
                # if you change the program counter, it undoes your call to emu_stop()..
                if address != userData["targetVA"]:
                    self.skipInstruction(userData)
            elif self.isRetInstruction(address):
                #self.stopEmulation(userData)
                self.skipInstruction(userData)
                return

        except Exception as e:
            self.logger.debug("exception in _guided_hook @%s: %s" %
                          (self.hexString(address), e))
            print("exception in _guided_hook @%s: %s" %
                          (self.hexString(address), e))
            self.stopEmulation(userData)
            #qexit(1)

    # scans ahead from address until IDA finds an instruction
    def _scanForCode(self, address):
        while self.safe_print_insn_mnem(address) == "":
            address = next_head(address, get_inf_attr(INF_MAX_EA))
        return address
        
    # checks ARM mode for address and aligns address accordingly
    def _handleThumbMode(self, address):
        if self.isThumbMode(address):
            self.mu.reg_write(self.regs["pc"], self.getRegVal("pc") | 1)
            self.mode = UC_MODE_THUMB
        else:
            self.mu.reg_write(self.regs["pc"], self.getRegVal("pc") & ~1)
            self.mode = UC_MODE_ARM

    # called when an iterate target is reached
    def _targetHit(self, uc, address, userData):
        # argv isn't perfect, we don't know the number of args to a given function and we're not considering SSE args
        # this is just a convenience, use the emulator object if you have specific needs
        try:
            if self.arch == UC_ARCH_X86:
                if self.mode == UC_MODE_64:
                    if self.filetype == "MACHO" or self.filetype == "ELF":
                        argv = [
                            self.getRegVal("rdi"),
                            self.getRegVal("rsi"),
                            self.getRegVal("rdx"),
                            self.getRegVal("rcx"),
                            self.getRegVal("r8"),
                            self.getRegVal("r9")]
                    else:
                        argv = [
                            self.getRegVal("rcx"),
                            self.getRegVal("rdx"),
                            self.getRegVal("r8"),
                            self.getRegVal("r9")]
                else:
                    sp = self.getRegVal("esp")
                    argv = [
                        struct.unpack("<I", str(uc.mem_read(sp, 4)))[0],
                        struct.unpack("<I", str(uc.mem_read(sp + 4, 4)))[0],
                        struct.unpack("<I", str(uc.mem_read(sp + 8, 4)))[0],
                        struct.unpack("<I", str(uc.mem_read(sp + 12, 4)))[0],
                        struct.unpack("<I", str(uc.mem_read(sp + 16, 4)))[0],
                        struct.unpack("<I", str(uc.mem_read(sp + 20, 4)))[0]]
            elif self.arch == UC_ARCH_ARM:
                argv = [
                    self.getRegVal("R0"),
                    self.getRegVal("R1"),
                    self.getRegVal("R2"),
                    self.getRegVal("R3")]
            elif self.arch == UC_ARCH_ARM64:
                argv = [
                    self.getRegVal("X0"),
                    self.getRegVal("X1"),
                    self.getRegVal("X2"),
                    self.getRegVal("X3"),
                    self.getRegVal("X4"),
                    self.getRegVal("X5"),
                    self.getRegVal("X6"),
                    self.getRegVal("X7")]
            userData["targetCallback"](self, address, argv, userData)
        except Exception as e:
            self.logger.debug("exception in targetCallback function: %s" % e)
            print("exception in targetCallback function: %s" % e)
        userData["visitedTargets"].append(address)

    def _isBadBranch(self, userData):
        if self.arch == UC_ARCH_ARM64:
            if self.safe_print_insn_mnem(userData["currAddr"]) in ["BR", "BREQ"] and get_operand_type(
                userData["currAddr"], 0) == 1:
                if self.safe_print_insn_mnem(self.mu.reg_read(self.regs[self.safe_print_operand(userData["currAddr"], 
                    0)])) == "":
                    return True
        elif self.arch == UC_ARCH_X86:
            if (self.safe_print_insn_mnem(userData["currAddr"]) == "jmp" and get_operand_type(userData["currAddr"], 0) 
                == 1):
                if (self.safe_print_insn_mnem(self.mu.reg_read(self.regs[self.safe_print_operand(userData["currAddr"], 
                    0)])) == ""):
                    self.logger.debug("bad branch detected @%s" %
                                  self.hexString(userData["currAddr"]))
                    return True

    # returns a list of lists containing all possible paths through a function as basic block ids
    # or returns the index of a single list for the first path found leading to end_bb
    def _explore(self, start_bb, end_bb=None):
        if hasattr(self, 'explorePaths') == False:
            self.explorePaths = [[]]
            self.explorePathIdx = 0

        #set_cmt(start_bb.start_ea, "%d" % start_bb.id, 0)

        # optional target bb found, back out
        if end_bb is not None and end_bb == start_bb.id:
            self.explorePaths[self.explorePathIdx].append(start_bb.id)
            return self.explorePathIdx

        # handle loops by treating them like a terminating bb
        if start_bb.id in self.explorePaths[self.explorePathIdx]:
            # forging a new path
            self.explorePaths.append(
                deepcopy(self.explorePaths[self.explorePathIdx]))
            self.explorePathIdx += 1
            return None

        # add this bb to our list
        self.explorePaths[self.explorePathIdx].append(start_bb.id)

        # if we are a terminating bb stop recursing
        if self.isTerminatingBB(start_bb):
            # forging a new path
            self.explorePaths.append(
                deepcopy(self.explorePaths[self.explorePathIdx]))
            self.explorePathIdx += 1
            self.explorePaths[self.explorePathIdx].pop()
            return None

        # visit successor bbs
        for w in start_bb.succs():
            r = self._explore(w, end_bb)
            if r is not None:
                return r
        self.explorePaths[self.explorePathIdx].pop()

    def _findValidMemAddress(self):
        # start at 0x10000 to avoid collision with null mem references during emulation
        highest = 0x10000
        for region in self.mu.mem_regions():
            if region[1] > highest:
                highest = region[1]
        for segVA in Segments():
            endVA = get_segm_end(segVA)
            if endVA > highest:
                highest = endVA
        highest += PAGESIZE
        return self.pageAlignUp(highest)

    # stack setup
    # stack pointer will begin in the middle of allocated stack size
    def _buildStack(self):
        self.stack = self.allocEmuMem(self.stackSize) + self.stackSize / 2
        self.mu.mem_write(self.stack - self.stackSize /
                          2, "\x00" * self.stackSize)

    def _enableVFP(self):
        if self.arch == UC_ARCH_ARM:
            # for ARM, we must run this code in order to enable vector instructions in our emulator
            """
            mov.w r0, #0xf00000
            mcr p15, #0x0, r0, c1, c0, #0x2
            isb sy
            mov.w r3, #0x40000000
            vmsr fpexc, r3
            """
            #ENABLE_VFP_CODE = "\x0f\x06\xa0\xe3\x50\x0f\x01\xee\x6f\xf0\x7f\xf5\x01\x31\xa0\xe3\x10\x3a\xe8\xee"
            #self.emulateBytes(ENABLE_VFP_CODE, {}, [])
            tmp = self.mu.reg_read(UC_ARM_REG_C1_C0_2)
            self.mu.reg_write(UC_ARM_REG_C1_C0_2, tmp | (0xf << 20))
            self.mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        elif self.arch == UC_ARCH_ARM64:
            """
            https://static.docs.arm.com/ddi0487/ca/DDI0487C_a_armv8_arm.pdf
            MRS X2, CPACR_EL1
            ORR X2, X2, #0x300000 # <-- set bits 20,21 to disable trapping for FP related instructions
            MSR  CPACR_EL1, X2
            NOP # <-- handle Unicorn bug
            """
            ENABLE_VFP_CODE = "\x42\x10\x38\xd5\x42\x04\x6c\xb2\x42\x10\x18\xd5\x1f\x20\x03\xd5"
            self.emulateBytes(ENABLE_VFP_CODE)

    # prepare thread context
    def _prepEmuContext(self, registerState, argv):
        mu = self.mu
        for reg in self.regs:
            mu.reg_write(self.regs[reg], 0)
        mu.reg_write(self.regs["sp"], self.stack)
        for reg in registerState:
            val = registerState[reg]
            if type(val) is str:
                mem = self.allocEmuMem(len(val))
                mu.mem_write(mem, val)
                val = mem
            elif type(val) == int or type(val) == long:
                pass
            else:
                self.logger.debug("incorrect type for %s" % reg)
                return None
            mu.reg_write(self.regs[reg], val)
            registerState[reg] = val

        # setup stack args
        for i in range(0, len(argv)):
            if type(argv[i]) is str:
                mem = self.allocEmuMem(len(argv[i]))
                mu.mem_write(mem, argv[i])
                argv[i] = mem
                val = mem
            elif type(argv[i]) == int or type(argv[i]) == long:
                val = argv[i]
            else:
                self.logger.debug("incorrect type for argv[%d]" % (i))
                return None


            mu.mem_write(self.getRegVal("sp") + i *
                         self.size_pointer, struct.pack(self.pack_fmt, val))

    def getUserStorage(self):
        return self.user_storage