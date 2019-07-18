import logging

from RamPack import RamPack
from Magic import Magic


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
