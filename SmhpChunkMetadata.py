"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: SmhpChunkMetadata.py

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

from Tools import Tools


class SmhpChunkMetadata(Tools):
    """
    The SmhpChunkMetadata class corresponds to the Windows 10
    SMHP_CHUNK_METADATA structure. The file is currently a placeholder on a
    lower-priority structure attributed to it not having changed recently.
    The structure contains fields used to decode information from the chunk
    key identified in ST_DATA_MGR.sLocalTree. The structure is one of the few
    involved with page decompression that has not changed through the evolution
    of the algorithm. This is not a guarantee of future behavior.
    """
    def __init__(self, loglevel=logging.INFO):
        self.logger = logging.getLogger("SMHP_CHUNK_METADATA")
        self.logger.setLevel(loglevel)
        self.fe = self.get_flare_emu()
        return

    def _dump(self):
        """
         Architecture agnostic function used to dump all located fields.
         """
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