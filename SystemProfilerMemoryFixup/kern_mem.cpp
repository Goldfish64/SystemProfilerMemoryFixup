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

// Find:    BF 02 00 00 00 E8 XX XX XX XX
// Replace: B8 08 00 00 00 0F 1F 44 00 00
static const uint8_t replaceMemBytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static const size_t findMemBytesCount = arrsize(replaceMemBytes);
static uint8_t findMemBytesSystemInformation[findMemBytesCount];
static uint8_t findMemBytesSPMemoryReporter[findMemBytesCount];

static UserPatcher::BinaryModPatch patchBytesMemSPMemoryReporter {
    CPU_TYPE_X86_64,
    0,
    findMemBytesSPMemoryReporter,
    replaceMemBytes,
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
    replaceMemBytes,
    findMemBytesCount,
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

bool SPFX::patchMemoryUpgradability(spfx_binary *binSPMemoryReporter, spfx_binary *binSystemInformation) {
    DBGLOG(SPFX_PLUGIN, "Enabling memory upgradeablity state patches...");
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
        // Locate where ASI_IsPlatformFeatureEnabled is called.
        //
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
            SYSLOG(SPFX_PLUGIN, "Failed to locate ASI_IsPlatformFeatureEnabled");
            return false;
        }
        
        copyMem(binFinds[i], &buffer[address], findMemBytesCount);
    }
    
    patchesSPMemoryReporter->push_back(patchBytesMemSPMemoryReporter);
    patchesSPMemoryReporter->push_back(patchStringAir);
    patchesSystemInformation->push_back(patchMemBytesSystemInformation);
    patchesSystemInformation->push_back(patchStringAir);
    return true;
}
