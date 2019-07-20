import logging

from Magic import Magic
from SmkmStoreMgr import SmkmStoreMgr
from Smkm import Smkm
from SmkmStoreMetadata import SmkmStoreMetadata
from SmkmStore import SmkmStore
from StStore import StStore
from StDataMgr import StDataMgr

def main():
    Magic()._dump32()
    SmkmStoreMgr()._dump32()
    Smkm()._dump32()
    SmkmStoreMetadata()._dump32()
    SmkmStore()._dump32()
    StStore()._dump32()
    StDataMgr()._dump32()
    return

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
