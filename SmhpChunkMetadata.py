import logging

from RamPack import RamPack


class SmhpChunkMetadata(RamPack):
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMHP_CHUNK_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        return

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