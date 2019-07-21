# Win10Deflate Automated Structure Extraction
`Win10Deflate` currently consists of the FLARE team's Volatility & Rekall plugins designed to support the extraction of compressed pages located in the RAM-backed virtual store. The structures required to decompress these pages are undocumented and ever-changing. The `Win10Deflate Auto` project locates these structures and extracts the corresponding magics & field-offsets of interest for use in FLARE's Volatility & Rekall plugins. The project leverages Tom Bennett's `FLARE-EMU` utility, which provides a series of helper functions to lower the barrier of entry to using the `Unicorn Engine` for emulation.

## Setup
1. Clone repository
2. If `flare_emu` is installed on your machine, skip to `Usage`
3. Use `git submodule init` to clone the `FLARE-EMU` repository locally

## Usage
The `Win10Deflate Auto` script is designed to work in an `IDA Pro 7.x` environment in the context of a Windows 10 `ntoskrnl.exe`. Use `Alt+F7` or `File > Script File` to load `win10deflate_auto.py`.

## Output
Expected output will look similar to the output below (`Win10.1809.x64`).
```
INFO:Magic:MAGIC.SmGlobals: 0x55a9c0
INFO:Magic:MAGIC.MmPagingFile: 0x43e5e0
INFO:SMKM_STORE_MGR:SMKM_STORE_MGR.sSmKm: 0x0
INFO:SMKM_STORE_MGR:SMKM_STORE_MGR.sGlobalTree: 0x1c0
INFO:SMKM:SMKM.SmkmStoreMetadataArray: 0x0
INFO:SMKM_STORE_METADATA:SMKM_STORE_METADATA.Size: 0x28
INFO:SMKM_STORE_METADATA:SMKM_STORE_METADATA.pSmkmStore: 0x0
INFO:SMKM_STORE:SMKM_STORE.StStore: 0x0
INFO:SMKM_STORE:SMKM_STORE.pCompressedRegionPtrArray: 0x1848
INFO:SMKM_STORE:SMKM_STORE.StoreOwnerProcess: 0x19a8
INFO:ST_STORE:ST_STORE.StDataMgr: 0x50
INFO:ST_STORE:ST_DATA_MGR.sLocalTree: 0x0
INFO:ST_STORE:ST_DATA_MGR.ChunkMetadata: 0xc0
INFO:ST_STORE:ST_DATA_MGR.SmkmStore: 0x320
INFO:ST_STORE:ST_DATA_MGR.RegionSizeMask: 0x328
INFO:ST_STORE:ST_DATA_MGR.RegionLSB: 0x32c
INFO:ST_STORE:ST_DATA_MGR.CompressionFormat: 0x3e0
```

## Functionality
The `Win10Deflate` automation script relies on known function arguments, callstacks, order of operation, and data manipulation within `ntoskrnl.exe`'s Store Manager functions. By leveraging emulation via `FLARE-EMU`, arguments and structures can be injected into the system, traced, and then located to calculate field offsets in structures of interest.

## Additional Reading
1. TODO - Rekall & Volatility Announcement Blog
1. TODO - Deep Dive
1. TODO - Win10Deflate Automation Blog