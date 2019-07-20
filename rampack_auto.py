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
