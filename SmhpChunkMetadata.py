import logging

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
        self.logger = logging.getLogger("SMHP_CHUNK_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump32(self):
        return

    def _dump64(self):

    def shcm32_chunkptrarray(self):
        return

    def shcm32_bitvalue(self):
        return

    def shcm32_pagerecordsperchunkmask(self):
        return

    def shcm32_pagerecordsize(self):
        return

    def shcm32_chunkpageheadersize(self):
        return