import logging

from Magic import Magic
from SmkmStoreMgr import SmkmStoreMgr
from Smkm import Smkm
from SmkmStoreMetadata import SmkmStoreMetadata
from SmkmStore import SmkmStore
from StStore import StStore
from StDataMgr import StDataMgr

def main():
    Magic()._dump()
    SmkmStoreMgr()._dump()
    Smkm()._dump()
    SmkmStoreMetadata()._dump()
    SmkmStore()._dump()
    StStore()._dump()
    StDataMgr()._dump()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
