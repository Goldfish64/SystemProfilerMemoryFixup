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
static const uint8_t findAir[] = "MacBookAir";
static const uint8_t replaceAir[] = "MacBookXir";
static UserPatcher::BinaryModPatch patchAir {
    CPU_TYPE_X86_64,
    findAir,
    replaceAir,
    strlen(reinterpret_cast<const char *>(findAir)),
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

// MacBookAir name patches.
static const uint8_t findProc2Str[] = { 0x48, 0x85, 0xC0, 0x74, 0x26 };
static const uint8_t replaceProc2Str[] = { 0x48, 0x85, 0xC0, 0x71, 0x26 };
static UserPatcher::BinaryModPatch patchProc2Str {
    CPU_TYPE_X86_64,
    findProc2Str,
    replaceProc2Str,
    arrsize(findProc2Str),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};

// 49 89 D7 41 89 F4 41 89 FE
// 4D 31 FF 41 89 F4 41 89 FE

//static const uint8_t findTest[] = { 0x49, 0x89, 0xD7, 0x41, 0x89, 0xF4, 0x41, 0x89, 0xFE };
//static const uint8_t replaceTest[] = { 0x4D, 0x31, 0xFF, 0x41, 0x89, 0xF4, 0x41, 0x89, 0xFE };
//static uint8_t findTest[]; // // 48 31 C0 C3
/*static uint8_t findTest[32];
static uint8_t replaceTest[32];// = { 0x48, 0x31, 0xC0, 0xC3 };

static UserPatcher::BinaryModPatch patchTest {
    CPU_TYPE_X86_64,
    findTest,
    replaceTest,
    arrsize(replaceTest),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};*/

//static uint8_t replaceTest[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xFF, 0x48, 0x8D, 0x35, 0xD7, 0x1F, 0x00, 0x00, 0xBA, 0x00, 0x01, 0x00, 0x08, 0xE8, 0xEA, 0x1A, 0x00, 0x00, 0x5D, 0xC3} ;


//
// Patches to return arbitrary CPU name from _ASI_CopyCPUKind
//
//

// Find (generated at runtime):
//   Starting instructions of _ASI_CopyCPUKind with 12 bytes of immediate previous function
//
// Replace (partially generated at runtime; starting zeroes and jmp address):
//   push rbp
//   mov rbp, rsp
//   jmp [findASICopyCPUKind2]
//
static uint8_t replaceASICopyCPUKind1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x48, 0x89, 0xE5, 0xE9, 0x94, 0x01, 0x00, 0x00 };
static uint8_t findASICopyCPUKind1[arrsize(replaceASICopyCPUKind1)];

// Find (generated at runtime):
//
//
// Replace (partially generated at runtime, address of STRING):
//   xor rdi, rdi
//   lea rsi, qword [STRING]
//   mov edx, 0x8000100
//   call...
//
static uint8_t replaceASICopyCPUKind2[] = { 0x48, 0x31, 0xFF, 0x48, 0x8D, 0x35, 0x3E, 0x1E, 0x00, 0x00, 0xBA, 0x00, 0x01, 0x00, 0x08, 0xE8 };
static uint8_t findASICopyCPUKind2[arrsize(replaceASICopyCPUKind2)];

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
static uint8_t replaceASICopyCPUKind3[] = { 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90 };
static uint8_t findASICopyCPUKind3[arrsize(replaceASICopyCPUKind3)];


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
        0,
        1,
        UserPatcher::FileSegment::SegmentTextText,
        SectionActive
    }
};



// 48 31 FF - xor rdi, rdi
// 48 8D 35 3E 1E 00 00 - lea        rsi, qword [aIntelCoreSolo] - relative
// BA 00 01 00 08 E8 XX XX XX XX - mov edx, 0x8000100 / call




// Find:    BF 02 00 00 00 E8 XX XX XX XX
// Replace: B8 08 00 00 00 0F 1F 44 00 00
static const size_t patchMemBytesCount = 10;
static const uint8_t replaceMemBytes[patchMemBytesCount] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00 };

// Patching info for System Information binary.
static uint8_t findMemBytesSystemInformation[patchMemBytesCount] = { };
static UserPatcher::BinaryModPatch patchMemBytesSystemInformation {
    CPU_TYPE_X86_64,
    findMemBytesSystemInformation,
    replaceMemBytes,
    patchMemBytesCount,
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};

// Patching info for SPMemoryReporter binary.
static uint8_t findMemBytesSPMemoryReporter[patchMemBytesCount] = { };
static UserPatcher::BinaryModPatch patchMemBytesSPMemoryReporter {
    CPU_TYPE_X86_64,
    findMemBytesSPMemoryReporter,
    replaceMemBytes,
    patchMemBytesCount,
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
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

// BinaryModInfo array containing all patches required. Paths changed in 10.15.
static UserPatcher::BinaryModInfo binaryMemPatchesCatalina[] {
    { binPathSystemInformationCatalina, &patchMemBytesSystemInformation, 1},
    { binPathSPMemoryReporter, &patchMemBytesSPMemoryReporter, 1},
    { binPathSystemInformationCatalina, &patchAir, 1 },
    { binPathSPMemoryReporter, &patchAir, 1 },
    { binPathSPPlatformReporter, patchesSPPlatformReporter, arrsize(patchesSPPlatformReporter) },
    { binPathAppleSystemInfo, patchesAppleSystemInfo, arrsize(patchesAppleSystemInfo) }
    //{ binPathAppleSystemInfo, &patchTest3, 1 }//,
   // { binPathAppleSystemInfo, &patchProcStr, 1 }
};

// BinaryModInfo array containing all patches required for 10.14 and below.
static UserPatcher::BinaryModInfo binaryMemPatches[] {
    { binPathSystemInformation, &patchMemBytesSystemInformation, 1},
    { binPathSPMemoryReporter, &patchMemBytesSPMemoryReporter, 1},
    { binPathSystemInformation, &patchAir, 1 },
    { binPathSPMemoryReporter, &patchAir, 1 }
};

// BinaryModInfo array containing all patches required for 10.8.
// 10.8 does not have ASI_IsPlatformFeatureEnabled or strings in SPMemoryReporter.
static UserPatcher::BinaryModInfo binaryPatchesML[] {
    { binPathSystemInformation, &patchAir, 1 },
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

static bool buildPatch(KernelPatcher &patcher, const char *path, uint8_t *findBuffer) {
    DBGLOG("SystemProfilerMemoryFixup", "buildPatches() start");
    
    // Get contents of binary.
    size_t outSize;
    uint8_t *buffer = FileIO::readFileToBuffer(path, outSize);
    if (buffer == NULL) {
        DBGLOG("SystemProfilerMemoryFixup", "Failed to read binary: %s\n", path);
        return false;
    }
    
    // Find where ASI_IsPlatformFeatureEnabled is called.
    off_t index = 0;
    for (off_t i = 0; i < outSize; i++) {
        if (buffer[i] == 0xBF && buffer[i+1] == 0x02 && buffer[i+2] == 0x00
            && buffer[i+3] == 0x00 && buffer[i+4] == 0x00 && buffer[i+5] == 0xE8) {
            index = i;
            break;
        }
    }
    
    // If we found no match, we can't go on.
    if (index == 0) {
        DBGLOG("SystemProfilerMemoryFixup", "Failed to get index into binary: %s\n", path);
        Buffer::deleter(buffer);
        return false;
    }
    
    // Build find pattern.
    uint8_t *bufferOffset = buffer + index;
    for (uint32_t i = 0; i < patchMemBytesCount; i++)
        findBuffer[i] = bufferOffset[i];
    
    // Free buffer.
    Buffer::deleter(buffer);
    return true;
}

static void buildPatchesCatalina(void *user, KernelPatcher &patcher) {
    // Build patches for binaries.
    if (!buildPatch(patcher, binPathSystemInformationCatalina, findMemBytesSystemInformation)
        || !buildPatch(patcher, binPathSPMemoryReporter, findMemBytesSPMemoryReporter))
        return;
    
    // Load patches into Lilu for 10.15+.
   // lilu.onProcLoadForce(&procInfoCatalina, 1, nullptr, nullptr, binaryMemPatchesCatalina, arrsize(binaryMemPatchesCatalina));
   // lilu.onProcLoadForce(&procInfoCatalina, 1, nullptr, nullptr, binaryPciPatchesCatalina, arrsize(binaryPciPatchesCatalina));
}

static void buildPatchesOld(void *user, KernelPatcher &patcher) {
    // Build patches for binaries.
    if (!buildPatch(patcher, binPathSystemInformation, findMemBytesSystemInformation)
        || !buildPatch(patcher, binPathSPMemoryReporter, findMemBytesSPMemoryReporter))
        return;
    
    // Load patches into Lilu for 10.9 to 10.14.
    lilu.onProcLoadForce(&procInfo, 1, nullptr, nullptr, binaryMemPatches, arrsize(binaryMemPatches));
}

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


static void buildPatches(void *user, KernelPatcher &patcher) {
    KernelVersion kernelVersion = getKernelVersion();
    
    MachInfo *infoAsiFramework = MachInfo::create();
    if (infoAsiFramework == NULL) {
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
        return;
    }
    
    if (infoAsiFramework->init(&binPathAppleSystemInfo) != KERN_SUCCESS
        || infoAsiFramework->setRunningAddresses(0) != KERN_SUCCESS) {
        infoAsiFramework->deinit();
        MachInfo::deleter(infoAsiFramework);
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
        return;
    }
    
    mach_vm_address_t address = infoAsiFramework->solveSymbol("_ASI_CopyCPUKind");
    if (address == 0) {
        infoAsiFramework->deinit();
        MachInfo::deleter(infoAsiFramework);
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
        return;
    }
    
    IOLog("SPFX SystemProfilerMemoryFixup::buildPatches() Found _ASI_CopyCPUKind @ 0x%X\n", address);
    
    
    mach_vm_address_t addressCoreSolo = 0x38a7;
    IOLog("SPFX SystemProfilerMemoryFixup::buildPatches() Found aIntelCoreSolo @ 0x%X\n", addressCoreSolo);
    
    uint8_t *buf = readBytes(binPathAppleSystemInfo, address, 4096);
    
    mach_vm_address_t cfStringAddress = 0;
    for (uint32_t i = 0; i < 4096 - sizeof (uint32_t) - 2; i++) {
        if (buf[i] == 0xBA && *((uint32_t*)&buf[i+1]) == 0x8000100 && buf[i+1+sizeof(uint32_t)] == 0xE8) {
            DBGLOG("SPFX", "Found CFString statement at 0x%X", address + i);
            cfStringAddress = address + i;
            break;
        }
    }
    
    // E9 94 01 00 00 - jmp to section below - add actual calc
    
    
    // 48 31 FF - xor rdi, rdi
    // 48 8D 35 3E 1E 00 00 - lea        rsi, qword [aIntelCoreSolo] - relative
    // BA 00 01 00 08 E8 XX XX XX XX - mov edx, 0x8000100 / call
    // 5D C3 - pop rbp / ret
    
    uint8_t *buffer = readBytes(binPathAppleSystemInfo, address - 12, arrsize(findASICopyCPUKind1));
    if (buffer == NULL) {
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
    }
    
    //lmemcpy(findTest, buffer, arrsize(findTest));
    lmemcpy (findASICopyCPUKind1, buffer, arrsize (findASICopyCPUKind1));
    for (int i = 0; i < 12; i++) {
        replaceASICopyCPUKind1[i] = findASICopyCPUKind1[i];
    }
    
    IOLog("SPFX1 0x%X 0x%X 0x%X 0x%X\n", findASICopyCPUKind1[0], findASICopyCPUKind1[1], findASICopyCPUKind1[2], findASICopyCPUKind1[3]);
    
    uint8_t *buffer2 = readBytes(binPathAppleSystemInfo, cfStringAddress - 10, arrsize(findASICopyCPUKind2));
    if (buffer2 == NULL) {
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
    }
    
    //lmemcpy(findTest, buffer, arrsize(findTest));
    lmemcpy (findASICopyCPUKind2, buffer2, arrsize (findASICopyCPUKind2));
    
    IOLog("SPFX2 0x%X 0x%X 0x%X 0x%X\n", findASICopyCPUKind2[0], findASICopyCPUKind2[1], findASICopyCPUKind2[2], findASICopyCPUKind2[3]);
    
    
    uint8_t *buffer3 = readBytes(binPathAppleSystemInfo, cfStringAddress + 17, arrsize(findASICopyCPUKind3));
    if (buffer3 == NULL) {
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
    }
    
    //lmemcpy(findTest, buffer, arrsize(findTest));
    lmemcpy (findASICopyCPUKind3, buffer3, arrsize (findASICopyCPUKind3));
    
    IOLog("SPFX3 0x%X 0x%X 0x%X 0x%X\n", findASICopyCPUKind3[0], findASICopyCPUKind3[1], findASICopyCPUKind3[2], findASICopyCPUKind3[3]);
    
    
    MachInfo *infoSPPlatform = MachInfo::create();
    if (infoSPPlatform == NULL) {
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
        return;
    }
    
    if (infoSPPlatform->init(&binPathSPPlatformReporter) != KERN_SUCCESS
        || infoSPPlatform->setRunningAddresses(0) != KERN_SUCCESS) {
        infoAsiFramework->deinit();
        MachInfo::deleter(infoAsiFramework);
        panic("SystemProfilerMemoryFixup::buildPatches(): Failed to create mach info for AppleSystemInfo\n");
        return;
    }
    
    mach_vm_address_t address3 = infoSPPlatform->solveSymbol("imp___stubs__ASI_CopyCPUKind");
    
    IOLog("SPFX SystemProfilerMemoryFixup::buildPatches() Found imp___stubs__ASI_CopyCPUKind @ 0x%X\n", address3);
    
    // Get contents of binary.
    size_t outSize;
    uint8_t *buffer4 = FileIO::readFileToBuffer(binPathSPPlatformReporter, outSize);
    if (buffer == NULL) {
        //DBGLOG("SystemProfilerMemoryFixup", "Failed to read binary: %s\n", path);
        return;
    }
    
    // Find where ASI_IsPlatformFeatureEnabled is called.
    off_t index = 0;
    for (off_t i = 0; i < outSize; i++) {
        if (buffer4[i] == 0xBF
            && buffer4[i+1] == 0x01
            && buffer4[i+2] == 0x00
            && buffer4[i+3] == 0x00
            && buffer4[i+4] == 0x00
            && buffer4[i+5] == 0xE8) {
            index = i + 5;
            break;
        }
    }
    IOLog("SPFX SystemProfilerMemoryFixup::buildPatches() Found patch point @ 0x%X\n", index);
    
    lmemcpy(findSPPlatformReporterHideCPU, &buffer4[index], arrsize(findSPPlatformReporterHideCPU));
    
    IOSleep(5000);
    
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
        lilu.onPatcherLoad(buildPatchesCatalina);
        lilu.onProcLoadForce(procInfoCatalina, arrsize(procInfoCatalina), nullptr, nullptr, binaryMemPatchesCatalina, arrsize(binaryMemPatchesCatalina));

        
    } else if (getKernelVersion() >= KernelVersion::Mavericks) {
        // Load callback so we can determine patterns to search for.
        lilu.onPatcherLoad(buildPatchesOld);
        
    } else if (getKernelVersion() == KernelVersion::MountainLion) {
        // 10.8 requires only a single patch.
        lilu.onProcLoadForce(&procInfo, 1, nullptr, nullptr, binaryPatchesML, arrsize(binaryPatchesML));
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
