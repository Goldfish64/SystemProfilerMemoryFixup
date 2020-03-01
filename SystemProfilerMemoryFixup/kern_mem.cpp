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
// MacBookAir name patch - System Information, SPMemoryReporter
//
static const uint8_t findStringAir[] = "MacBookAir";
static const uint8_t replaceStringAir[] = "MacBookXir";
static UserPatcher::BinaryModPatch patchStringAir {
    CPU_TYPE_X86_64,
    0,
    findStringAir,
    replaceStringAir,
    strlen(reinterpret_cast<const char *>(findStringAir)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SECTION_ACTIVE
};

//
// Disables call to ASI_IsPlatformFeatureEnabled(0x2) - System Information, SPMemoryReporter
//
// Find (generated at runtime):
//   call ASI_IsPlatformFeatureEnabled
//
// Replace (when enabling memory upgradeability):
//   xor rax, rax
//   nop
//   nop
//
// Replace (when disabling memory upgradeability):
//   mov eax, 0x1
//
static const uint8_t replaceMemBytesEnabled[]   = { 0x48, 0x31, 0xC0, 0x90, 0x90 };
static const uint8_t replaceMemBytesDisabled[]  = { 0xB8, 0x01, 0x00, 0x00, 0x00 };
static const size_t findMemBytesCount = arrsize(replaceMemBytesEnabled);
static uint8_t findMemBytesSystemInformation[findMemBytesCount];
static uint8_t findMemBytesSPMemoryReporter[findMemBytesCount];
static UserPatcher::BinaryModPatch patchBytesMemSPMemoryReporter {
    CPU_TYPE_X86_64,
    0,
    findMemBytesSPMemoryReporter,
    replaceMemBytesEnabled,
    findMemBytesCount,
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};
static UserPatcher::BinaryModPatch patchMemBytesSystemInformation {
    CPU_TYPE_X86_64,
    0,
    findMemBytesSystemInformation,
    replaceMemBytesEnabled,
    findMemBytesCount,
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

bool SPFX::patchMemoryUpgradability(spfx_binary *binSPMemoryReporter, spfx_binary *binSystemInformation, bool enabled) {
    DBGLOG(SPFX_PLUGIN, "Enabling memory upgradeability state patches (memory upgradeability = %u)...", enabled);
    spfx_binary *binaries[] = {
        binSPMemoryReporter,
        binSystemInformation
    };
    uint8_t *binFinds[] = {
        findMemBytesSPMemoryReporter,
        findMemBytesSystemInformation
    };
    
    for (int i = 0; i < arrsize(binaries); i++) {
        const uint8_t *buffer = binaries[i]->Buffer;
        size_t bufferSize = binaries[i]->Size;
        
        //
        // Locate where ASI_IsPlatformFeatureEnabled(0x2) is called.
        //
        off_t address = 0;
        for (off_t i = 0; i < bufferSize - sizeof(uint64_t); i++) {
            if (buffer[i] == 0xBF
                && buffer[i + 1] == 0x02
                && buffer[i + 2] == 0x00
                && buffer[i + 3] == 0x00
                && buffer[i + 4] == 0x00
                && buffer[i + 5] == 0xE8) {
                address = i + 5;
                break;
            }
        }
        if (address == 0) {
            SYSLOG(SPFX_PLUGIN, "Failed to locate ASI_IsPlatformFeatureEnabled");
            return false;
        }
        
        copyMem(binFinds[i], &buffer[address], findMemBytesCount);
    }
    
    if (enabled) {
        //
        // Apply MacBookAir whitelist patch.
        //
        patchesSPMemoryReporter->push_back(patchStringAir);
        patchesSystemInformation->push_back(patchStringAir);
    } else {
        //
        // Use disabled patches instead.
        //
        patchBytesMemSPMemoryReporter.replace = replaceMemBytesDisabled;
        patchMemBytesSystemInformation.replace = replaceMemBytesDisabled;
    }
    
    patchesSPMemoryReporter->push_back(patchBytesMemSPMemoryReporter);
    patchesSystemInformation->push_back(patchMemBytesSystemInformation);
    return true;
}
