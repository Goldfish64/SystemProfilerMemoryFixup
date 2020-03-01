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
// Prevents localized string from being looked up - AppleSystemInfo
//
static const uint8_t findStringNoSerialNumberFound[] = "NoSerialNumberFound";
static const uint8_t replaceStringNoSerialNumberFound[] = "XoSerialNumberFound";
static UserPatcher::BinaryModPatch patchStringNoSerialNumberFound {
    CPU_TYPE_X86_64,
    0,
    findStringNoSerialNumberFound,
    replaceStringNoSerialNumberFound,
    strlen(reinterpret_cast<const char *>(findStringNoSerialNumberFound)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SECTION_ACTIVE
};

//
// Default no serial string - AppleSystemInfo
//
static const uint8_t findStringNotFound[] = "NotFound";
static const uint8_t replaceStringNotFound[] = "        ";
static UserPatcher::BinaryModPatch patchStringNotFound {
    CPU_TYPE_X86_64,
    0,
    findStringNotFound,
    replaceStringNotFound,
    strlen(reinterpret_cast<const char *>(findStringNotFound)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SECTION_ACTIVE
};

//
// _ASI_CopyFormattedSerialNumber patch - AppleSystemInfo
//
// Find (generated at runtime):
//   call _CopyIOPlatformSerialNumberString
//
// Replace:
//   xor rax, rax
//   nop
//   nop
//
static const uint8_t replaceASICopyFormattedSerial[] = { 0x48, 0x31, 0xC0, 0x90, 0x90 };
static uint8_t findASICopyFormattedSerial[arrsize(replaceASICopyFormattedSerial)];
static UserPatcher::BinaryModPatch patchASICopyFormattedSerial {
    CPU_TYPE_X86_64,
    0,
    findASICopyFormattedSerial,
    replaceASICopyFormattedSerial,
    arrsize(findASICopyFormattedSerial),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SECTION_ACTIVE
};

bool SPFX::patchSerial(spfx_binary *binAppleSystemInfo, spfx_binary *binSPPlatformReporter) {
    DBGLOG(SPFX_PLUGIN, "Enabling serial visibility patches...");

    uint8_t *bufferAppleSystemInfo      = binAppleSystemInfo->Buffer;
    size_t bufferSizeAppleSystemInfo    = binAppleSystemInfo->Size;
    
    //
    // Locate _ASI_CopyFormattedSerialNumber.
    //
    mach_vm_address_t addressCopyFormattedSerial = binAppleSystemInfo->MachInfo->solveSymbol("_ASI_CopyFormattedSerialNumber");
    if (addressCopyFormattedSerial == 0) {
        SYSLOG(SPFX_PLUGIN, "Failed to locate symbol _ASI_CopyFormattedSerialNumber");
        return false;
    }
    DBGLOG(SPFX_PLUGIN, "Located symbol _ASI_CopyFormattedSerialNumber @ 0x%llX", addressCopyFormattedSerial);
    
    for (off_t i = addressCopyFormattedSerial; i < bufferSizeAppleSystemInfo - sizeof (uint64_t); i++) {
        if (bufferAppleSystemInfo[i] == 0xE8) {
            addressCopyFormattedSerial = i;
            break;
        }
    }
    copyMem(findASICopyFormattedSerial, &bufferAppleSystemInfo[addressCopyFormattedSerial], arrsize(findASICopyFormattedSerial));
    
    patchesAppleSystemInfo->push_back(patchASICopyFormattedSerial);
    patchesAppleSystemInfo->push_back(patchStringNoSerialNumberFound);
    patchesAppleSystemInfo->push_back(patchStringNotFound);
    return true;
}
