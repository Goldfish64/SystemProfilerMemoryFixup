/*
 * Copyright (c) 2018-2019 John Davis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_file.hpp>

#define SPFX_PLUGIN     "SPFX"

typedef struct {
    uint32_t MajorType;
    uint32_t MinorType;
    uint32_t NumberOfCores;
    uintptr_t MarketingNameOffset;
    uintptr_t TechnicalNameOffset;
} AsiProcessorInfo;

// Pathes to binaries.
static const char *binPathSystemInformation = "/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
static const char *binPathSystemInformationCatalina = "/System/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
static const char *binPathSPMemoryReporter = "/System/Library/SystemProfiler/SPMemoryReporter.spreporter/Contents/MacOS/SPMemoryReporter";

static const char *binPathSPPlatformReporter = "/System/Library/SystemProfiler/SPPlatformReporter.spreporter/Contents/MacOS/SPPlatformReporter";


static const char *binPathAppleSystemInfo = "/System/Library/PrivateFrameworks/AppleSystemInfo.framework/Versions/A/AppleSystemInfo";


static const uint32_t SectionActive = 1;

// MacBookAir name patches.
static const uint8_t findStringAir[] = "MacBookAir";
static const uint8_t replaceStringAir[] = "MacBookXir";
static UserPatcher::BinaryModPatch patchStringAir {
    CPU_TYPE_X86_64,
    findStringAir,
    replaceStringAir,
    strlen(reinterpret_cast<const char *>(findStringAir)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SectionActive
};

// MacBookAir name patches.
static const uint8_t findProcStr[] = "Processors";
static const uint8_t replaceProcStr[] = "Xrocessors";
static UserPatcher::BinaryModPatch patchProcStr {
    CPU_TYPE_X86_64,
    findProcStr,
    replaceProcStr,
    strlen(reinterpret_cast<const char *>(findProcStr)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SectionActive
};



//
// Patches to return arbitrary CPU name from _ASI_CopyCPUKind
//
//

// Patch 1
//
// Find (generated at runtime):
//   Starting instructions of _ASI_CopyCPUKind with 12 bytes of immediate previous function
//
// Replace (partially generated at runtime; starting zeroes and jmp address):
//   push rbp
//   mov rbp, rsp
//   jmp [findASICopyCPUKind2]
//
static const size_t findASICopyCPUKind1Offset = 12;
static const size_t replaceASICopyCPUKind1JmpOffset = findASICopyCPUKind1Offset + 5;
static uint8_t replaceASICopyCPUKind1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x48, 0x89, 0xE5, 0xE9, 0x94, 0x01, 0x00, 0x00 };
static uint8_t findASICopyCPUKind1[arrsize(replaceASICopyCPUKind1)];

// Patch 2
//
// Find (generated at runtime):
//  ... (10 bytes)
//  mov edx, 0x8000100
//  call...
//
// Replace (partially generated at runtime, address of STRING):
//   xor rdi, rdi
//   lea rsi, qword [STRING]
//   mov edx, 0x8000100
//   call...
//
static const size_t findASICopyCPUKind2Offset = 10;
static const uint8_t replaceASICopyCPUKind2[] = { 0x48, 0x31, 0xFF, 0x48, 0x8D, 0x35, 0x3E, 0x1E, 0x00, 0x00, 0xBA, 0x00, 0x01, 0x00, 0x08, 0xE8 };
static uint8_t findASICopyCPUKind2[arrsize(replaceASICopyCPUKind2)];

// Patch 3
//
// Find (generated at runtime):
//
//
// Replace:
//   pop rbp
//   ret
//   nop
//   nop
//   nop
//   nop
//
static const uint8_t replaceASICopyCPUKind3[] = { 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90 };
static uint8_t findASICopyCPUKind3[arrsize(replaceASICopyCPUKind3)];// = { 0x48, 0x8B ,0x73, 0x18, 0x4C, 0x89 };


//
// AppleSystemInfo patches.
//
static UserPatcher::BinaryModPatch patchesAppleSystemInfo[] {
    {
        CPU_TYPE_X86_64,
        findASICopyCPUKind1,
        replaceASICopyCPUKind1,
        arrsize(findASICopyCPUKind1),
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    },
    {
        CPU_TYPE_X86_64,
        findASICopyCPUKind2,
        replaceASICopyCPUKind2,
        arrsize(findASICopyCPUKind2),
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    },
    {
        CPU_TYPE_X86_64,
        findASICopyCPUKind3,
        replaceASICopyCPUKind3,
        arrsize(findASICopyCPUKind3),
        1, // Required to skip over similar pattern used for patch 2 above.
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    }
};


//
// Patch to hide CPU name from SPPlatformReporter.
//
// Find (generated at runtime):
//   call _ASI_CopyCPUKind
//
// Replace:
//   xor rax, rax
//   nop
//   nop
//
static const uint8_t replaceSPPlatformReporterHideCPU[] = { 0x48, 0x31, 0xC0, 0x90, 0x90 };
static uint8_t findSPPlatformReporterHideCPU[arrsize(replaceSPPlatformReporterHideCPU)];

//
// SPPlatformReporter patches.
//
static UserPatcher::BinaryModPatch patchesSPPlatformReporter[] {
    {
        CPU_TYPE_X86_64,
        findSPPlatformReporterHideCPU,
        replaceSPPlatformReporterHideCPU,
        arrsize(findSPPlatformReporterHideCPU),
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    }
};




// Find:    BF 02 00 00 00 E8 XX XX XX XX
// Replace: B8 08 00 00 00 0F 1F 44 00 00
static const uint8_t replaceMemBytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const size_t findMemBytesCount = arrsize(replaceMemBytes);
static uint8_t findMemBytesSystemInformation[findMemBytesCount];
static uint8_t findMemBytesSPMemoryReporter[findMemBytesCount];

//
// SPMemoryReporter patches.
//
static UserPatcher::BinaryModPatch patchesSPMemoryReporter[] {
    {
        CPU_TYPE_X86_64,
        findMemBytesSPMemoryReporter,
        replaceMemBytes,
        findMemBytesCount,
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    },
    patchStringAir
};


//
// System Information patches.
//
static UserPatcher::BinaryModPatch patchesSystemInformation[] {
    {
        CPU_TYPE_X86_64,
        findMemBytesSystemInformation,
        replaceMemBytes,
        findMemBytesCount,
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    },
    patchStringAir
};





// BinaryModInfo array containing all patches required. Paths changed in 10.15.
static UserPatcher::BinaryModInfo binaryMemPatchesCatalina[] {
    { binPathSystemInformationCatalina, patchesSystemInformation, arrsize(patchesSystemInformation)},
    { binPathSPMemoryReporter, patchesSPMemoryReporter, arrsize(patchesSPMemoryReporter)},
    { binPathSPPlatformReporter, patchesSPPlatformReporter, arrsize(patchesSPPlatformReporter) },
    { binPathAppleSystemInfo, patchesAppleSystemInfo, arrsize(patchesAppleSystemInfo) }
    //{ binPathAppleSystemInfo, &patchTest3, 1 }//,
   // { binPathAppleSystemInfo, &patchProcStr, 1 }
};

// BinaryModInfo array containing all patches required for 10.14 and below.
static UserPatcher::BinaryModInfo binaryMemPatches[] {
    //{ binPathSystemInformation, &patchMemBytesSystemInformation, 1},
    //{ binPathSPMemoryReporter, &patchMemBytesSPMemoryReporter, 1},
};

// BinaryModInfo array containing all patches required for 10.8.
// 10.8 does not have ASI_IsPlatformFeatureEnabled or strings in SPMemoryReporter.
static UserPatcher::BinaryModInfo binaryPatchesML[] {
   // { binPathSystemInformation, &patchAir, 1 },
};

// Find:    31 C9 84 C0 0F 95 C1 89 C8 5D C3
// Replace: B8 01 00 00 00 90 90 90 90 5D C3
//
// Find:
// xor        ecx, ecx
// test       al, al
// setne      cl
// mov        eax, ecx
// pop        rbp
// ret
//
// Replace:
// mov        eax, 0x1
// nop
// nop
// nop
// nop
// pop        rbp
// ret
static const uint8_t findPciBytes[] = { 0x31, 0xC9, 0x84, 0xC0, 0x0F, 0x95, 0xC1, 0x89, 0xC8, 0x5D, 0xC3 };
static const uint8_t replacePciBytes[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x5D, 0xC3 };



// Patching info for PCI info in System Information binary.
static UserPatcher::BinaryModPatch patchPciBytesSystemInformation {
    CPU_TYPE_X86_64,
    findPciBytes,
    replacePciBytes,
    arrsize(findPciBytes),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};

// BinaryModInfo array containing PCI tab patches for Catalina.
static UserPatcher::BinaryModInfo binaryPciPatchesCatalina[] {
    { binPathSystemInformationCatalina, &patchPciBytesSystemInformation, 1},
};

// System Information process info.
static UserPatcher::ProcInfo procInfoCatalina[] =
    {
        {
        binPathSystemInformationCatalina, static_cast<uint32_t>(strlen(binPathSystemInformationCatalina)), 1
        },
        {
        binPathSPPlatformReporter, static_cast<uint32_t>(strlen(binPathSPPlatformReporter)), 1
        }
        
    };

// System Information process info.
static UserPatcher::ProcInfo procInfo = { binPathSystemInformation, static_cast<uint32_t>(strlen(binPathSystemInformation)), 1 };


// Replace:
// 48 31 C0 C3
//
// xor rax, rax
// ret

static uint8_t* readBytes(const char* fromPath, off_t atOffset, size_t numBytes)
{
    vnode_t node = NULL;
    
    vfs_context_t context = vfs_context_create(NULL);
    
    if (vnode_lookup(fromPath, 0, &node, context) != 0)
    {
        IOLog("NightShiftUnlocker::readBytes() Error: Failed to read bytes.\n");
        
        vfs_context_rele(context);
        
        return NULL;
    }
    
    uint8_t* buffer = new uint8_t[numBytes];
    
    if (FileIO::readFileData(buffer, atOffset, numBytes, node, context) != 0)
    {
        IOLog("NightShiftUnlocker::readBytes() Error: Failed to read bytes.\n");
        
        delete [] buffer;
        
        buffer = NULL;
    }
    
    vnode_put(node);
    
    vfs_context_rele(context);
    
    return buffer;
}

static void lmemcpy(void* dst, const void* src, size_t length)
{
    for (int index = 0; index < length; index++)
    {
        ((uint8_t*) dst)[index] = ((uint8_t*) src)[index];
    }
}

// _ASI_CPUSpeedInHz - returns CPU speed in Hz
// _ASI_NumberOfCPUs - returns number of processors
// _ASI_CopyCPUKind - returns name of CPU, used as key for looking up localized name


static bool buildPatchesSPPlatformReporter(void *user, KernelPatcher &patcher) {
    DBGLOG(SPFX_PLUGIN, "Generating patches for SPPlatformReporter");
    
    size_t bufferSize;
    uint8_t *buffer = FileIO::readFileToBuffer(binPathSPPlatformReporter, bufferSize);
    if (buffer == NULL) {
        SYSLOG(SPFX_PLUGIN, "Failed to read SPPlatformReporter binary: %s\n", binPathSPPlatformReporter);
        return false;
    }
    
    // Determine where _ASI_CopyCPUKind is called.
    //   mov edi, 0x1
    //   call...
    off_t address = 0;
    for (off_t i = 0; i < bufferSize + 5; i++) {
        if (buffer[i] == 0xBF
            && buffer[i + 1] == 0x01
            && buffer[i + 2] == 0x00
            && buffer[i + 3] == 0x00
            && buffer[i + 4] == 0x00
            && buffer[i + 5] == 0xE8) {
            address = i + 5;
            break;
        }
    }
    if (address == 0)
        return false;
    
    // Store find pattern.
    DBGLOG(SPFX_PLUGIN, "Found _ASI_CopyCPUKind @ 0x%llX", address);
    lmemcpy(findSPPlatformReporterHideCPU, &buffer[address], arrsize(findSPPlatformReporterHideCPU));
    return true;
}

static bool buildPatchesAppleSystemInfo(void *user, KernelPatcher &patcher) {
    DBGLOG(SPFX_PLUGIN, "Generating patches for AppleSystemInfo");
    
    MachInfo *machInfo = MachInfo::create();
    if (machInfo == NULL) {
        SYSLOG(SPFX_PLUGIN, "Failed to create mach info for AppleSystemInfo");
        return false;
    }
    
    if (machInfo->init(&binPathAppleSystemInfo) != KERN_SUCCESS
        || machInfo->setRunningAddresses(0) != KERN_SUCCESS) {
        machInfo->deinit();
        MachInfo::deleter(machInfo);
        SYSLOG(SPFX_PLUGIN, "Failed to init mach info for AppleSystemInfo");
        return false;
    }
    
    mach_vm_address_t addressCopyCPUKind = machInfo->solveSymbol("_ASI_CopyCPUKind");
    if (addressCopyCPUKind == 0) {
        machInfo->deinit();
        MachInfo::deleter(machInfo);
        SYSLOG(SPFX_PLUGIN, "Failed to locate symbol _ASI_CopyCPUKind");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located symbol _ASI_CopyCPUKind @ 0x%llX", addressCopyCPUKind);
    machInfo->deinit();
    MachInfo::deleter(machInfo);
    
    size_t bufferSize;
    uint8_t *buffer = FileIO::readFileToBuffer(binPathAppleSystemInfo, bufferSize);
    if (buffer == NULL) {
        SYSLOG(SPFX_PLUGIN, "Failed to read AppleSystemInfo binary: %s\n", binPathAppleSystemInfo);
        return false;
    }
    
    if (addressCopyCPUKind <= findASICopyCPUKind1Offset
        || addressCopyCPUKind < findASICopyCPUKind2Offset
        || addressCopyCPUKind < arrsize(findASICopyCPUKind3)
        || bufferSize < addressCopyCPUKind - findASICopyCPUKind1Offset + arrsize(findASICopyCPUKind1)) {
        SYSLOG(SPFX_PLUGIN, "Offset of symbol _ASI_CopyCPUKind is not valid.");
        return false;
    }
    
    // Copy patch 1.
    lmemcpy(findASICopyCPUKind1, &buffer[addressCopyCPUKind - findASICopyCPUKind1Offset], arrsize (findASICopyCPUKind1));
    lmemcpy(replaceASICopyCPUKind1, findASICopyCPUKind1, findASICopyCPUKind1Offset);
    
    // Generate find pattern for patch 2. TODO: Determine end bounds for function.
    //
    // Locate bytes directly before the first "call CFStringCreateWithCString".
    // Find:
    //   mov edx, 0x8000100
    //   call...
    //
    mach_vm_address_t addressCfString1 = 0;
    for (off_t i = addressCopyCPUKind; i < bufferSize - sizeof(uint32_t) - 1; i++) {
        if (buffer[i] == 0xBA && *((uint32_t*)&buffer[i + 1]) == 0x8000100) {
            // Search for call instruction within 16 bytes.
            for (off_t j = i + 1 + sizeof(uint32_t); j < i + 16 && j < bufferSize - sizeof(uint32_t) - 1; j++) {
                if (buffer[j] == 0xE8) {
                    addressCfString1 = j - sizeof(uint32_t) - 1 - findASICopyCPUKind2Offset;
                    break;
                }
            }
            if (addressCfString1 != 0)
                break;
        }
    }
    
    if (addressCfString1 == 0 ||
        bufferSize < addressCfString1 + arrsize(findASICopyCPUKind2)) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate CFStringCreateWithCString patch point 1");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located CFStringCreateWithCString patch point 1 @ 0x%llX", addressCfString1);
    
    // Copy patch 2.
    lmemcpy(findASICopyCPUKind2, &buffer[addressCfString1], arrsize(findASICopyCPUKind2));
    *(uint32_t*)(&replaceASICopyCPUKind1[replaceASICopyCPUKind1JmpOffset]) = (uint32_t)(addressCfString1 - (addressCopyCPUKind - findASICopyCPUKind1Offset + arrsize(findASICopyCPUKind1)));
    DBGLOG(SPFX_PLUGIN, "Short jump 0x%X", (uint32_t)(addressCfString1 - (addressCopyCPUKind - findASICopyCPUKind1Offset + arrsize(findASICopyCPUKind1))));
    
    for (int i = 0; i < arrsize(findASICopyCPUKind1); i++) {
        DBGLOG(SPFX_PLUGIN, "find1 (%u): 0x%X 0x%X", i, findASICopyCPUKind1[i], replaceASICopyCPUKind1[i]);
    }
    
    // Generate find pattern for patch 3.
    //
    // Locate bytes directly before the second "call CFStringCreateWithCString".
    // Start at previous offset with find buffer size and call instruction size added.
    // Find:
    //   mov edx, 0x8000100
    //   call...
    //
    mach_vm_address_t addressCfString2 = 0;
    for (off_t i = addressCfString1 + arrsize(findASICopyCPUKind2) + findASICopyCPUKind2Offset; i < bufferSize - sizeof(uint32_t) - 1; i++) {
        if (buffer[i] == 0xBA && *((uint32_t*)&buffer[i + 1]) == 0x8000100) {
            addressCfString2 = i;
            break;
        }
    }
    
    if (addressCfString2 == 0 ||
        bufferSize < addressCfString2 + arrsize(findASICopyCPUKind3)) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate CFStringCreateWithCString patch point 2");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located CFStringCreateWithCString patch point 2 @ 0x%llX", addressCfString2);
    lmemcpy(findASICopyCPUKind3, &buffer[addressCfString2], arrsize(findASICopyCPUKind3));
    
    return true;
}

static bool patchMemoryUpgradability(void *user, KernelPatcher &patcher) {
    DBGLOG(SPFX_PLUGIN, "Generating memory upgradeablity state patches...");
    
    // Catalina and higher has System Information in different location.
    const char *binPaths[] = {
        binPathSPMemoryReporter,
        getKernelVersion() >= KernelVersion::Catalina ? binPathSystemInformationCatalina : binPathSystemInformation
    };
    
    uint8_t *binFinds[] = {
        findMemBytesSPMemoryReporter,
        findMemBytesSystemInformation
    };
    
    
    for (int i = 0; i < arrsize(binPaths); i++) {
        size_t bufferSize;
        uint8_t *buffer = FileIO::readFileToBuffer(binPaths[i], bufferSize);
        if (buffer == NULL) {
            SYSLOG(SPFX_PLUGIN, "Failed to read binary: %s\n", binPaths[i]);
            return false;
        }
        
        // Locate where ASI_IsPlatformFeatureEnabled is called.
        off_t address = 0;
        for (off_t i = 0; i < bufferSize - 6; i++) {
            if (buffer[i] == 0xBF
                && buffer[i + 1] == 0x02
                && buffer[i + 2] == 0x00
                && buffer[i + 3] == 0x00
                && buffer[i + 4] == 0x00
                && buffer[i + 5] == 0xE8) {
                address = i;
                break;
            }
        }
        if (address == 0) {
            SYSLOG(SPFX_PLUGIN, "Failed to get patch point\n");
            Buffer::deleter(buffer);
            return false;
        }
        
        lmemcpy(binFinds[i], &buffer[address], findMemBytesCount);
        Buffer::deleter(buffer);
    }
    
    return true;
}

static void buildPatches(void *user, KernelPatcher &patcher) {

    
    
    buildPatchesSPPlatformReporter(user, patcher);
    buildPatchesAppleSystemInfo(user, patcher);
    patchMemoryUpgradability(user, patcher);
    IOSleep(5000);
    return;
    
    
   /* vnode_t node = NULL;
    
    vfs_context_t context = vfs_context_create(NULL);
    
    if (vnode_lookup(binPathAppleSystemInfo, 0, &node, context) != 0)
    {
        panic("NightShiftUnlocker::readBytes() Error: Failed to read bytes.\n");
        
        vfs_context_rele(context);
        
        return;
    }
    
    AsiProcessorInfo procInfo;
    size_t procTableSize = 0;
    mach_vm_address_t curAddress = address;
    //size_t procTableCount;
    
    uintptr_t lowest = 0;
    do {
        FileIO::readFileData(&procInfo, curAddress, sizeof (procInfo), node, context);
        curAddress += sizeof (procInfo);
        procTableSize += sizeof (procInfo);
        IOLog("SPFX: Got type 0x%X, subtype 0x%X\n", procInfo.MajorType, procInfo.MinorType);
        
        if ((lowest == 0 || procInfo.MarketingNameOffset < lowest) && procInfo.MarketingNameOffset > 0) {
            lowest = procInfo.MarketingNameOffset;
            IOLog("SPFX: new low 0x%X\n", lowest);
        }
    } while (procInfo.MarketingNameOffset != 0);
    
    vnode_put(node);
    
    vfs_context_rele(context);
    size_t procTableCount = procTableSize / sizeof(procInfo);
    
    
    patchTest.size = procTableSize;
    patchTest.find = readBytes(binPathAppleSystemInfo, address, procTableSize);
    patchTest.replace = readBytes(binPathAppleSystemInfo, address, procTableSize);
    
    AsiProcessorInfo *procTable = (AsiProcessorInfo*)patchTest.replace;
    for (int i = 0; i < procTableCount; i++) {
        procTable[i].MarketingNameOffset = lowest;
        procTable[i].TechnicalNameOffset = lowest;
    }
    IOLog("SPFX: %u entries, %u bytes\n", procTableCount, procTableSize);
    */
    
    

}

// Main function.
static void spmemfxStart() {
    DBGLOG("SystemProfilerMemoryFixup", "start");
            lilu.onPatcherLoad(buildPatches);
    
    // Are we on 10.15 or above?
    if (getKernelVersion() >= KernelVersion::Catalina) {
        // Load callback so we can determine patterns to search for.
        //lilu.onPatcherLoad(buildPatchesCatalina);
        lilu.onProcLoadForce(procInfoCatalina, arrsize(procInfoCatalina), nullptr, nullptr, binaryMemPatchesCatalina, arrsize(binaryMemPatchesCatalina));

        
    } else if (getKernelVersion() >= KernelVersion::Mavericks) {
        // Load callback so we can determine patterns to search for.
     //   lilu.onPatcherLoad(buildPatchesOld);
        
    } else if (getKernelVersion() == KernelVersion::MountainLion) {
        // 10.8 requires only a single patch.
       // lilu.onProcLoadForce(&procInfo, 1, nullptr, nullptr, binaryPatchesML, arrsize(binaryPatchesML));
    }
}

// Boot args.
static const char *bootargOff[] {
    "-spmemfxoff"
};
static const char *bootargDebug[] {
    "-spmemfxdbg"
};
static const char *bootargBeta[] {
    "-spmemfxbeta"
};

// Plugin configuration.
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    bootargOff,
    arrsize(bootargOff),
    bootargDebug,
    arrsize(bootargDebug),
    bootargBeta,
    arrsize(bootargBeta),
    KernelVersion::MountainLion,
    KernelVersion::Catalina,
    []() {
        spmemfxStart();
    }
};
