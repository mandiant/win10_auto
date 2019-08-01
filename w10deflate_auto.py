"""
Copyright 2019 FireEye, Inc.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: w10deflate_auto.py

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

"""
Description: The W10Deflate Auto automation framework is designed to reduce the level of effort
spent analyzing a Windows 10 kernel in search of undocumented structures corresponding to
the Store Manager's RAM-backed Virtual Store. The resolution of these structures enables
end-users to keep the Volatility & Rekall Win10Deflate plugins up-to-date.

Usage: python w10deflate_auto.py
Environment: IDA Pro
Context: Currently opened database of a Windows 10 ntoskrnl.exe file
"""
import logging

from Magic import Magic
from SmkmStoreMgr import SmkmStoreMgr
from Smkm import Smkm
from SmkmStoreMetadata import SmkmStoreMetadata
from SmkmStore import SmkmStore
from StStore import StStore
from StDataMgr import StDataMgr

import idc

def main(loglevel=logging.INFO):
    Magic(loglevel=loglevel)._dump()
    SmkmStoreMgr(loglevel=loglevel)._dump()
    Smkm(loglevel=loglevel)._dump()
    SmkmStoreMetadata(loglevel=loglevel)._dump()
    SmkmStore(loglevel=loglevel)._dump()
    StStore(loglevel=loglevel)._dump()
    StDataMgr(loglevel=loglevel)._dump()

    return


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if idc.get_name_ea_simple("_KiSystemStartup@4") == -1:
        logging.warning("Launch script from within an ntoskrnl IDB with PDB symbols loaded")
    else:
        main(loglevel=logging.INFO)
