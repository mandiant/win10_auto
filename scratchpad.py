# Functions that are used in 

def eHook(uc, address, size, user_data):
    print "eHook"
    print user_data

def cHook(uc, address, size, userData):
    print "chook"
    print uc
    print address
    print size
    print userData

regState = {'ecx':0x0}
fe = EmuHelper()
fe.emulateRange(0x433814, registerState=regState, endAddr=0x433844)
fe.getRegVal('ecx')



for insn in self.iter_fn(self.cs, addr_smfereadinitiate):
    if insn.id == capstone.x86.X86_INS_CALL:
        if insn.operands[0].type == capstone.x86.X86_OP_IMM:
            call_offset = insn.operands[0].imm
            if call_offset == addr_exacquirepushlock:
                print idc.GetDisasm(insn.address)




        # Doesn't appear to stop emulator, need to revert to alternate means of endaddr calculation
        # Doesn't stop because IP is modified after this hook, which resets state of stop emu
        def cHook(uc, address, size, userData):
            self.logger.info("CallHook @ {0}".format(hex(address)))
            fe = userData["EmuHelper"]
            cs = self.get_cs()
            for insn in cs.disasm(idc.GetManyBytes(address, size), address):
                if insn.id == capstone.x86.X86_INS_CALL:
                    if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        call_offset = insn.operands[0].imm
                        if call_offset == addr_exacquirepushlock:
                            print "stopping"
                            fe.stopEmulation(userData)
                            return


# test case for regs_write...
import capstone
capstone.cs_version()
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
cs.detail = True
# and  eax, 7FFF0000h
for insn in cs.disasm("250000FF7F".decode('hex'), 0x1000):
    i = insn
print i.regs_write


# reg ctx in uc
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
uc.context_restore()
uc.reg_read(unicorn.x86_const.UC_X86_REG_ESI)





        """
        (startAddr, endAddr) = self.locate_call_in_fn("SmStCheckLockInProgressRegionComplete", "SmKmStoreHelperCheckWaitCommand")
        lp_smkmstore = 0x20000000L
        def pHook(self, mu, userData, funcStart):
            fe = userData['EmuHelper']
            user_storage = fe.getUserStorage()
            user_storage['lp_smkmstore'] = fe.loadBytes("\x00"*0x1000*2, addr=lp_smkmstore)
            fe.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, user_storage['lp_smkmstore'])
            fe.mu.reg_write(unicorn.x86_const.UC_X86_REG_EDX, int("SMVR".encode('hex'), 16))

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook, emuHook=self.eHookTrace)
        """

        # isolates the call block I'm interested in
        t_filtered = []
        for t in self.fe.getUserStorage()['trace']:
            t_filtered.append(t)
            if capstone.x86.X86_GRP_JUMP in t['cs_insn'].groups:
                endAddr = t['cs_insn'].address
                self.logger.debug("jump class @ {}".format(hex(endAddr)))
                break

        self.fe.mu.context_restore(t_filtered[-1]['uc_ctx'])
        user_storage = self.fe.getUserStorage()





# get all callpaths
# use tom's code for resolution
# integrate into flare-emu iterate (origin= & depth=)

def track(start,end,depth=0):
    current = []
    #do a func check
    
    for x0 in XrefsTo(end):
        x0_fn = get_func_attr(x0.frm, FUNCATTR_START)
        if x0_fn == start:
            print "done"
            print Name(x0_fn)
        else:
            for x1 in XrefsTo(x0_fn):
                x1_fn = get_func_attr(x1.frm, FUNCATTR_START)
                if x1_fn == start:
                    print "done @ 1"
                    print Name(x1_fn)



def fn_path(origin, destination, fpath=[]):
    for x in XrefsTo(destination):
        x_fn = get_func_attr(x.frm, FUNCATTR_START)
        if x_fn == origin:
            fpath.append(x_fn)
            return fpath
    
    for x in XrefsTo(destination):
        x_fn = get_func_attr(x.frm, FUNCATTR_START)
        fpath.append(x_fn)
        return check_xrefs(origin, x_fn, fpath)