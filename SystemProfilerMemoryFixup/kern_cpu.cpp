/*
* Copyright (c) 2020 John Davis
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

#include "kern_spfx.hpp"

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
//   xor rdi, rdi       ; Allocator arg in next patch, NULL = default
//   mov edx, 0x8000100 ; Encoding arg in next patch.
//   jmp [findASICopyCPUKind2]
//
static uint8_t replaceASICopyCPUKind1[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xFF, 0xBA, 0x00, 0x01, 0x00, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00 };
static uint8_t findASICopyCPUKind1[arrsize(replaceASICopyCPUKind1)];
static const size_t findASICopyCPUKind1Offset = 12;
static const size_t replaceASICopyCPUKind1JmpOffset = arrsize(replaceASICopyCPUKind1) - sizeof(uint32_t);
static UserPatcher::BinaryModPatch patchASICopyCPUKind1 {
    CPU_TYPE_X86_64,
    0,
    findASICopyCPUKind1,
    replaceASICopyCPUKind1,
    arrsize(findASICopyCPUKind1),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

// Patch 2
//
// Find (generated at runtime):
//  ... (10 bytes)
//  mov edx, 0x8000100
//  ...
//  call...
//
// Replace (partially generated at runtime, address of STRING):
//   lea rsi, qword [STRING]
//   call...
//
static uint8_t replaceASICopyCPUKind2[] = { 0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, 0xE8 };
static uint8_t findASICopyCPUKind2[arrsize(replaceASICopyCPUKind2)];
static const size_t findASICopyCPUKind2Offset = 7;
static const size_t replaceASICopyCPUKind2NameOffset = 3;
static UserPatcher::BinaryModPatch patchASICopyCPUKind2 {
    CPU_TYPE_X86_64,
    0,
    findASICopyCPUKind2,
    replaceASICopyCPUKind2,
    arrsize(findASICopyCPUKind2),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

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
static uint8_t findASICopyCPUKind3[arrsize(replaceASICopyCPUKind3)];
static UserPatcher::BinaryModPatch patchASICopyCPUKind3 {
    CPU_TYPE_X86_64,
    0,
    findASICopyCPUKind3,
    replaceASICopyCPUKind3,
    arrsize(findASICopyCPUKind3),
    1, // Required to skip over similar pattern used for patch 2 above.
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

//
// CPU name string patch.
//
static uint8_t findStringASICPUName[64];
static uint8_t replaceStringASICPUName[64];
static UserPatcher::BinaryModPatch patchStringASICPUName {
    CPU_TYPE_X86_64,
    0,
    findStringASICPUName,
    replaceStringASICPUName,
    arrsize(findStringASICPUName),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SECTION_ACTIVE
};

//
// Patch to hide CPU name from SPPlatformReporter.
//
// Find (generated at runtime):
//   mov edi, 0x1
//   call _ASI_CopyCPUKind
//
// Replace:
//   xor rax, rax
//   nop
//   nop
//
static const uint8_t replaceSPPlatformReporterHideCPU[] = { 0x48, 0x31, 0xC0, 0x90, 0x90 };
static uint8_t findSPPlatformReporterHideCPU[arrsize(replaceSPPlatformReporterHideCPU)];
static UserPatcher::BinaryModPatch patchSPPlatformReporterHideCPU {
    CPU_TYPE_X86_64,
    0,
    findSPPlatformReporterHideCPU,
    replaceSPPlatformReporterHideCPU,
    arrsize(findSPPlatformReporterHideCPU),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

// _ASI_CPUSpeedInHz - returns CPU speed in Hz
// _ASI_NumberOfCPUs - returns number of processors
// _ASI_CopyCPUKind - returns name of CPU, used as key for looking up localized name

bool SPFX::patchCPUName(spfx_binary *binAppleSystemInfo, spfx_binary *binSPPlatformReporter) {
    DBGLOG(SPFX_PLUGIN, "Enabling patches for CPU name...");
    
    uint8_t *bufferAppleSystemInfo      = binAppleSystemInfo->Buffer;
    size_t bufferSizeAppleSystemInfo    = binAppleSystemInfo->Size;
    uint8_t *bufferSPPlatformReporter   = binSPPlatformReporter->Buffer;
    size_t bufferSizeSPPlatformReporter = binSPPlatformReporter->Size;

    //
    // Patch SPPlatformReporter to hide CPU name first.
    //
    
    // Determine where _ASI_CopyCPUKind is called.
    //   mov edi, 0x1
    //   call...
    off_t address = 0;
    for (off_t i = 0; i < bufferSizeSPPlatformReporter + 5; i++) {
        if (bufferSPPlatformReporter[i] == 0xBF
            && bufferSPPlatformReporter[i + 1] == 0x01
            && bufferSPPlatformReporter[i + 2] == 0x00
            && bufferSPPlatformReporter[i + 3] == 0x00
            && bufferSPPlatformReporter[i + 4] == 0x00
            && bufferSPPlatformReporter[i + 5] == 0xE8) {
            address = i + 5;
            break;
        }
    }
    if (address == 0) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate _ASI_CopyCPUKind");
        return false;
    }
    
    // Store find pattern.
    DBGLOG(SPFX_PLUGIN, "Found _ASI_CopyCPUKind @ 0x%llX", address);
    copyMem(findSPPlatformReporterHideCPU, &bufferSPPlatformReporter[address], arrsize(findSPPlatformReporterHideCPU));
    
    //
    // Patch AppleSystemInfo to return arbitrary CPU name.
    //
    //
    // Locate _ASI_CopyCPUKind function.
    //
    mach_vm_address_t addressCopyCPUKind = binAppleSystemInfo->MachInfo->solveSymbol("_ASI_CopyCPUKind");
    if (addressCopyCPUKind == 0) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate symbol _ASI_CopyCPUKind");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located symbol _ASI_CopyCPUKind @ 0x%llX", addressCopyCPUKind);
    
    //
    // Locate _gMajorMinorTypesTable table, containing CPU string to type mappings.
    //
    mach_vm_address_t addressMajorMinorTypesTable = binAppleSystemInfo->MachInfo->solveSymbol("_gMajorMinorTypesTable");
    if (addressMajorMinorTypesTable == 0) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate symbol _gMajorMinorTypesTable");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located symbol _gMajorMinorTypesTable @ 0x%llX", addressMajorMinorTypesTable);
    
    //
    // Determine lowest available offset for CPU name use.
    //
    uintptr_t cpuNameOffset = 0;
    AsiProcessorInfo *procTable = (AsiProcessorInfo*)(&bufferAppleSystemInfo[addressMajorMinorTypesTable]);
    while (procTable->MarketingNameOffset != 0) {
        DBGLOG(SPFX_PLUGIN, "Maj: 0x%X Min: 0x%X Cores: 0x%X Market Name: 0x%X Tech Name: 0x%X", procTable->MajorType, procTable->MinorType, procTable->NumberOfCores, procTable->MarketingNameOffset, procTable->TechnicalNameOffset);
        if (cpuNameOffset == 0 || procTable->MarketingNameOffset < cpuNameOffset)
            cpuNameOffset = procTable->MarketingNameOffset;
        procTable++;
    }
    if (cpuNameOffset == 0) {
        SYSLOG(SPFX_PLUGIN, "Failed to determine offset for CPU name");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located string offset @ 0x%llX", cpuNameOffset);
    
    size_t strLen = strlen("glub glub inside™");
    copyMem(findStringASICPUName, &bufferAppleSystemInfo[cpuNameOffset], arrsize(findStringASICPUName));
    copyMem(replaceStringASICPUName, "glub glub inside™", strLen);
    
    if (addressCopyCPUKind <= findASICopyCPUKind1Offset
        || addressCopyCPUKind < findASICopyCPUKind2Offset
        || addressCopyCPUKind < arrsize(findASICopyCPUKind3)
        || bufferSizeAppleSystemInfo < addressCopyCPUKind - findASICopyCPUKind1Offset + arrsize(findASICopyCPUKind1)) {
        SYSLOG(SPFX_PLUGIN, "Offset of symbol _ASI_CopyCPUKind is not valid.");
        return false;
    }
    
    //
    // Copy patch 1.
    //
    // This replaces the start of _ASI_CopyCPUKind with a short jump to the
    //   next patched part of the function below.
    //
    copyMem(findASICopyCPUKind1, &bufferAppleSystemInfo[addressCopyCPUKind - findASICopyCPUKind1Offset], arrsize (findASICopyCPUKind1));
    copyMem(replaceASICopyCPUKind1, findASICopyCPUKind1, findASICopyCPUKind1Offset);
    
    //
    // Generate find pattern for patch 2. TODO: Determine end bounds for function.
    //
    // Locate bytes directly before the first "call CFStringCreateWithCString".
    // Find:
    //   mov edx, 0x8000100
    //   call...
    //
    mach_vm_address_t addressCfString1 = 0;
    DBGLOG(SPFX_PLUGIN, "Starting search 1 @ 0x%llX", addressCopyCPUKind);
    for (off_t i = addressCopyCPUKind; i < bufferSizeAppleSystemInfo - sizeof(uint32_t) - 1; i++) {
        if ((bufferAppleSystemInfo[i] == 0xBA) && (*((uint32_t*)&bufferAppleSystemInfo[i + 1]) == 0x08000100)) {
            DBGLOG(SPFX_PLUGIN, "mtach search 1 @ 0x%llX 0x%llX", i, bufferAppleSystemInfo[i]);
            // Search for call instruction within 16 bytes.
            for (off_t j = i + 1 + sizeof(uint32_t); j < i + 16 && j < bufferSizeAppleSystemInfo - sizeof(uint32_t) - 1; j++) {
                if (bufferAppleSystemInfo[j] == 0xE8) {
                    addressCfString1 = j - findASICopyCPUKind2Offset;
                    break;
                }
            }
            if (addressCfString1 != 0)
                break;
        }
    }
    
    if (addressCfString1 == 0 ||
        bufferSizeAppleSystemInfo < addressCfString1 + arrsize(findASICopyCPUKind2)) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate CFStringCreateWithCString patch point 1");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located CFStringCreateWithCString patch point 1 @ 0x%llX", addressCfString1);
    
    //
    // Copy patch 2.
    //
    copyMem(findASICopyCPUKind2, &bufferAppleSystemInfo[addressCfString1], arrsize(findASICopyCPUKind2));
    uint32_t offsetShortJmp = (uint32_t)(addressCfString1 - (addressCopyCPUKind - findASICopyCPUKind1Offset + arrsize(findASICopyCPUKind1)));
    uint32_t offsetString   = (uint32_t)(cpuNameOffset - addressCfString1 - replaceASICopyCPUKind2NameOffset - sizeof(uint32_t));
    
    *(uint32_t*)(&replaceASICopyCPUKind1[replaceASICopyCPUKind1JmpOffset]) = offsetShortJmp;
    *(uint32_t*)(&replaceASICopyCPUKind2[replaceASICopyCPUKind2NameOffset]) = offsetString;
    DBGLOG(SPFX_PLUGIN, "Short jump 0x%X", offsetShortJmp);
    DBGLOG(SPFX_PLUGIN, "String location 0x%X", offsetString);
    
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
    for (off_t i = addressCfString1 + arrsize(findASICopyCPUKind2) + findASICopyCPUKind2Offset; i < bufferSizeAppleSystemInfo - sizeof(uint32_t) - 1; i++) {
        if (bufferAppleSystemInfo[i] == 0xBA && *((uint32_t*)&bufferAppleSystemInfo[i + 1]) == 0x8000100) {
            addressCfString2 = i;
            break;
        }
    }
    
    if (addressCfString2 == 0 ||
        bufferSizeAppleSystemInfo < addressCfString2 + arrsize(findASICopyCPUKind3)) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate CFStringCreateWithCString patch point 2");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located CFStringCreateWithCString patch point 2 @ 0x%llX", addressCfString2);
    
    copyMem(findASICopyCPUKind3, &bufferAppleSystemInfo[addressCfString2], arrsize(findASICopyCPUKind3));
    
    patchesSPPlatformReporter->push_back(patchSPPlatformReporterHideCPU);
    patchesAppleSystemInfo->push_back(patchASICopyCPUKind1);
    patchesAppleSystemInfo->push_back(patchASICopyCPUKind2);
    patchesAppleSystemInfo->push_back(patchASICopyCPUKind3);
    patchesAppleSystemInfo->push_back(patchStringASICPUName);
    return true;
}
