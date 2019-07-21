"""
Author: Omar Sardar <omar.sardar@fireeye.com>
Name: w10deflate_auto.py
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
    main(loglevel=logging.INFO)
