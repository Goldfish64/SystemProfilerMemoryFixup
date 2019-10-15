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

// Pathes to binaries.
static const char *binPathSystemInformation = "/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
static const char *binPathSystemInformationCatalina = "/System/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
static const char *binPathSPMemoryReporter = "/System/Library/SystemProfiler/SPMemoryReporter.spreporter/Contents/MacOS/SPMemoryReporter";

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

// 49 89 D7 41 89 F4 41 89 FE
// 4D 31 FF 41 89 F4 41 89 FE

static const uint8_t findTest[] = { 0x49, 0x89, 0xD7, 0x41, 0x89, 0xF4, 0x41, 0x89, 0xFE };
static const uint8_t replaceTest[] = { 0x4D, 0x31, 0xFF, 0x41, 0x89, 0xF4, 0x41, 0x89, 0xFE };
static UserPatcher::BinaryModPatch patchTest {
    CPU_TYPE_X86_64,
    findTest,
    replaceTest,
    arrsize(findTest),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};

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

// BinaryModInfo array containing all patches required. Paths changed in 10.15.
static UserPatcher::BinaryModInfo binaryMemPatchesCatalina[] {
    { binPathSystemInformationCatalina, &patchMemBytesSystemInformation, 1},
    { binPathSPMemoryReporter, &patchMemBytesSPMemoryReporter, 1},
    { binPathSystemInformationCatalina, &patchAir, 1 },
    { binPathSPMemoryReporter, &patchAir, 1 },
    { binPathAppleSystemInfo, &patchTest, 1 }
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
static UserPatcher::ProcInfo procInfoCatalina = { binPathSystemInformationCatalina, static_cast<uint32_t>(strlen(binPathSystemInformationCatalina)), 1 };

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
    lilu.onProcLoadForce(&procInfoCatalina, 1, nullptr, nullptr, binaryMemPatchesCatalina, arrsize(binaryMemPatchesCatalina));
    lilu.onProcLoadForce(&procInfoCatalina, 1, nullptr, nullptr, binaryPciPatchesCatalina, arrsize(binaryPciPatchesCatalina));
}

static void buildPatches(void *user, KernelPatcher &patcher) {
    // Build patches for binaries.
    if (!buildPatch(patcher, binPathSystemInformation, findMemBytesSystemInformation)
        || !buildPatch(patcher, binPathSPMemoryReporter, findMemBytesSPMemoryReporter))
        return;
    
    // Load patches into Lilu for 10.9 to 10.14.
    lilu.onProcLoadForce(&procInfo, 1, nullptr, nullptr, binaryMemPatches, arrsize(binaryMemPatches));
}

// Main function.
static void spmemfxStart() {
    DBGLOG("SystemProfilerMemoryFixup", "start");
    
    // Are we on 10.15 or above?
    if (getKernelVersion() >= KernelVersion::Catalina) {
        // Load callback so we can determine patterns to search for.
        lilu.onPatcherLoad(buildPatchesCatalina);
        
    } else if (getKernelVersion() >= KernelVersion::Mavericks) {
        // Load callback so we can determine patterns to search for.
        lilu.onPatcherLoad(buildPatches);
        
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
