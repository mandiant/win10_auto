"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: StDataMgr.py

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
import struct

import idc

from Tools import Tools


class StDataMgr(Tools):
    """
    Description: The StDataMgr class corresponds to the Windows 10 ST_DATA_MGR
    structure. The ST_DATA_MGR structure is nested within SMKM_STORE and
    contains additional information used to locate the compressed page from a
    region within the MemCompression minimal process.
    """
    def __init__(self, loglevel=logging.INFO):
        self.tools = super(StDataMgr, self).__init__()
        self.logger = logging.getLogger("ST_DATA_MGR")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
         Architecture agnostic function used to dump all located fields.
         """
        arch = 'x64' if self.Info.is_64bit() else 'x86'
        self.logger.info("sLocalTree: {0:#x}".format(self.Info.arch_fns[arch]['stdm_localtree'](self)))
        self.logger.info("ChunkMetadata: {0:#x}".format(self.Info.arch_fns[arch]['stdm_chunkmetadata'](self)))
        self.logger.info("SmkmStore: {0:#x}".format(self.Info.arch_fns[arch]['stdm_smkmstore'](self)))
        self.logger.info("RegionSizeMask: {0:#x}".format(self.Info.arch_fns[arch]['stdm_regionsizemask'](self)))
        self.logger.info("RegionLSB: {0:#x}".format(self.Info.arch_fns[arch]['stdm_regionlsb'](self)))
        self.logger.info("CompressionFormat: {0:#x}".format(self.Info.arch_fns[arch]['stdm_compressionformat'](self)))
        return

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_localtree(self):
        """
        This B+TREE is nested within the ST_DATA_MGR and contains leaf nodes of type ST_PAGE_ENTRY.
        The ST_PAGE_ENTRY structure contains two fields- the SM_PAGE_KEY and a 32-bit chunk key. The
        chunk key is encoded with region information used to ultimately locate an ST_PAGE_RECORD
        structure (see ST_PAGE_RECORD), from which a compressed page can be found. This structure
        has historically been at offset 0. Function can be updated if this changes in the future.
        """
        return 0

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_chunkmetadata(self):
        """
        The SMHP_CHUNK_METADATA contains information used to locate the compressed page's corresponding
        ST_PAGE_RECORD, using information derived from the chunk key. See SMHP_CHUNK_METADATA for
        additional information. This function relies on the first argument to SmhHpChunkAlloc remaining
        constant. Disassembly snippet from Windows 10 1809 x86 shown below.

        StDmpSinglePageAdd+2B0      lea     ecx, [ebx+6Ch]
        StDmpSinglePageAdd+2B3      call    _SmHpChunkAlloc@4 ; SmHpChunkAlloc(x)
        """
        (startAddr, endAddr) = self.locate_call_in_fn("?StDmpSinglePageAdd", "SmHpChunkAlloc")
        self.fe.iterate([endAddr], self.tHook)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        return self.fe.getRegVal(reg_cx)

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_smkmstore(self):
        """
        This function relies on the first argument to SmStReleaseVirtualRegion remaining constant.
        Disassembly snippet from Windows 10 1809 x86 shown below.

        StReleaseRegion+26      mov     edi, [ebx+1C0h]
        StReleaseRegion+2C      test    byte ptr [edi+10F5h], 4
        StReleaseRegion+33      jz      loc_5B4984
        StReleaseRegion+39      push    0
        StReleaseRegion+3B      mov     ecx, edi
        StReleaseRegion+3D      call    ?SmStReleaseVirtualRegion@?$SMKM_STORE@USM_TRAITS@@@@SGJPAU1@KK@Z
        """
        (startAddr, endAddr) = self.locate_call_in_fn("?StReleaseRegion", "?SmStReleaseVirtualRegion")
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)
        reg_cx = 'rcx' if self.Info.is_64bit() else 'ecx'
        struct_fmt = "<Q" if self.Info.is_64bit() else "<I"

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        return pat.find(struct.pack(struct_fmt, self.fe.getRegVal(reg_cx)))

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_regionsizemask(self):
        """
        The region key located in the ST_PAGE_RECORD structure is encoded with an index in to
        SMKM_STORE.pCompressedRegionPointerArray, as well as an offset in to the pointer identified.
        This function relies on the arguments to StDmRegionEvict remaining constant. The x64 and x86
        implementation are slightly different due to differing calling conventions. Disassembly snippet
        from Windows 10 1809 x86 shown below.

        StDmRegionRemove+47     mov     eax, [ebx+1C4h]
        StDmRegionRemove+4D     push    ecx
        StDmRegionRemove+4E     inc     eax
        StDmRegionRemove+4F     push    eax
        StDmRegionRemove+50     push    ecx
        StDmRegionRemove+51     push    edx
        StDmRegionRemove+52     lea     edx, [ebx+20Ch]
        StDmRegionRemove+58     mov     ecx, ebx
        StDmRegionRemove+5A     call    ?StDmRegionEvict@?$ST_STORE@USM_TRAITS@@@@SGJPAU_ST_DATA_MGR@...

        """
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDmRegionRemove", "?StDmRegionEvict")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        if self.Info.is_64bit():
            reg_rsp = self.fe.getRegVal("rsp")
            stack_bytes = self.fe.getEmuBytes(reg_rsp, 0x28)
            third_arg = struct.unpack("<Q", stack_bytes[0x20:])[0]
        else:
            third_arg = self.fe.getArgv()[2]
        return pat.find(struct.pack("<I", third_arg - 1))  # Must be "<I" due to retrieval of a DWORD

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_regionlsb(self):
        """
        This function relies on data being manipulated prior to arriving at StRegionReadDereference.
        This works well due to the function being the first call made within StDeviceWorkItemCleanup.
        By prepopulating the ST_DATA_MGR structure with a known pattern, we can track it when the
        SHR operation occurs and derive the offset it originated from. Disassembly snippet from
        Windows 10 1809 x86 shown below.

        StDeviceWorkItemCleanup      ?StDeviceWorkItemCleanup@?$ST_STORE@USM_TRAITS...
        StDeviceWorkItemCleanup                      mov     edi, edi
        StDeviceWorkItemCleanup+2                    push    esi
        StDeviceWorkItemCleanup+3                    push    edi
        StDeviceWorkItemCleanup+4                    mov     esi, edx
        StDeviceWorkItemCleanup+6                    mov     edi, ecx
        StDeviceWorkItemCleanup+8                    mov     edx, [esi+0Ch]
        StDeviceWorkItemCleanup+B                    mov     ecx, [edi+1C8h]
        StDeviceWorkItemCleanup+11                   shr     edx, cl
        StDeviceWorkItemCleanup+13                   mov     ecx, edi
        StDeviceWorkItemCleanup+15                   call    ?StRegionReadDereference@?$ST_STORE@...
        """
        pat = self.patgen(8192)
        lp_stdatamgr = self.fe.loadBytes(pat)
        iHookData = {'pattern': None}

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        # Using an instruction hook because data in offset is difficult to track beyond arithmetic ops like shr
        def iHook(uc, address, size, userData):
            dis = idc.GetDisasm(address)
            if "shr" in dis[:3]:
                iHookData['pattern'] = struct.pack("<I", userData['EmuHelper'].uc.reg_read(userData["EmuHelper"].regs["cx"]))

        (startAddr, endAddr) = self.locate_call_in_fn("?StDeviceWorkItemCleanup", "?StRegionReadDereference")
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook, instructionHook=iHook)
        return pat.find(iHookData["pattern"])

    @Tools.Info.arch32
    @Tools.Info.arch64
    def stdm_compressionformat(self):
        """
        This field is a COMPRESSION_FORMAT_* enum value representing the compression format used for all
        pages in the respective store. It has been observed to consistently be COMPRESSION_FORMAT_XPRESS (0x3),
        Microsoft's XPRESS compression algorithm. It is a known argument to RtlDecompressBufferEx, so the
        only difference between x86 & x64 is it's location. The path to the function remains the same. Disassembly
        snippet from Windows 10 1809 x86 shown below.

        StDmSinglePageCopy+114      movzx   eax, word ptr [eax+224h]
        StDmSinglePageCopy+11B      lea     edx, [ebp+var_30]
        StDmSinglePageCopy+11E      push    edx
        StDmSinglePageCopy+11F      push    ecx
        StDmSinglePageCopy+120      push    edi
        StDmSinglePageCopy+121      mov     edi, [ebp+var_34]
        StDmSinglePageCopy+124      push    1000h
        StDmSinglePageCopy+129      push    edi
        StDmSinglePageCopy+12A      push    eax
        StDmSinglePageCopy+12B      call    _RtlDecompressBufferEx@28
        """
        pat = self.patgen(2048, size=2)  # Reduced pattern len & size to detect WORD
        lp_stdatamgr = self.fe.loadBytes(pat)

        def pHook(self, userData, funcStart):
            self.logger.debug("pre emulation hook loading ECX")
            userData['EmuHelper'].uc.reg_write(userData["EmuHelper"].regs["cx"], lp_stdatamgr)

        (startAddr, endAddr) = self.locate_call_in_fn("?StDmSinglePageCopy", ["_RtlDecompressBufferEx@", "RtlDecompressBufferEx"])
        self.fe.iterate([endAddr], self.tHook, preEmuCallback=pHook)
        if self.Info.is_64bit():
            pattern = struct.pack("H", self.fe.getRegVal("rcx"))
        else:
            reg_esp = self.fe.getRegVal("esp")
            pattern = self.fe.getEmuBytes(reg_esp, 0x2)  # Using 0x2 because this is a WORD field
        return pat.find(pattern)
