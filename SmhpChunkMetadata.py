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

"""
'_SMHP_CHUNK_METADATA': [None, {
    'ChunkPtrArray': [0x0, ['array', 32, ['pointer', ['void']]]],
    'BitValue': [0x108, ['unsigned int']],
    'PageRecordsPerChunkMask': [0x10C, ['unsigned int']],
    'PageRecordSize': [0x110, ['unsigned int']],
    'ChunkPageHeaderSize': [0x118, ['unsigned int']],
}],
"""
class SmhpChunkMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("ST_CHUNK_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump():
        return

    def chunk_ptr_array(self):
        return

    def bit_value(self):
        return

    def page_records_per_chunk_mask(self):
        return

    def page_record_size(self):
        return

    def chunk_page_header_size(self):
        return