/*
 * Copyright (c) 2018-2020 John Davis
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

#include "kern_spfx.hpp"

//
// Boot args.
//

static const char *bootargNoMemFix = "-spfxnomemfix";
static const char *bootargHideSerial = "-spfxhideserial";


static const uint32_t SectionActive = 1;

//
// String patches.
//



// IOPlatformSerialNumber name patch.
static const uint8_t findStringIOPlatformSerialNumber[] = "IOPlatformSerialNumber";
static const uint8_t replaceStringIOPlatformSerialNumber[] = "XOPlatformSerialNumber";
static UserPatcher::BinaryModPatch patchStringIOPlatformSerialNumber {
    CPU_TYPE_X86_64,
    0,
    findStringIOPlatformSerialNumber,
    replaceStringIOPlatformSerialNumber,
    strlen(reinterpret_cast<const char *>(findStringIOPlatformSerialNumber)),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextCstring,
    SectionActive
};




//
// Patch to disable fetching serial string (results in Unavailable in About This Mac).
//
static const uint8_t replaceASISerialNumberString[] = { 0x48, 0x85, 0xC0, 0x71, 0x02 };
static const uint8_t findASISerialNumberString[] = { 0x48, 0x85, 0xC0, 0x74, 0x02 };
static UserPatcher::BinaryModPatch patchASISerialNumberString {
    CPU_TYPE_X86_64,
    0,
    findASISerialNumberString,
    replaceASISerialNumberString,
    arrsize(findASISerialNumberString),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextText,
    SectionActive
};








static const uint8_t findStubBytes[] = { 0xFF, 0x25, 0x6A, 0x1C, 0x00, 0x00 };
static const uint8_t replStubBytes[] = { 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90 };
static UserPatcher::BinaryModPatch patchBytesStubCpuReporter {
    CPU_TYPE_X86_64,
    0,
    findStubBytes,
    replStubBytes,
    arrsize (findStubBytes),
    0,
    1,
    UserPatcher::FileSegment::SegmentTextStubs,
    SectionActive
};







static bool patchSerial(void *user, KernelPatcher &patcher) {
    DBGLOG(SPFX_PLUGIN, "Enabling patches for serial...");
    
    //patchesAppleSystemInfo->push_back(patchASISerialNumberString);
   // patchesSPPlatformReporter->push_back(patchStringIOPlatformSerialNumber);
    return true;
}

static SPFX spfx;

static const char *bootargOff = "-spfxoff";
static const char *bootargDebug = "-spfxdbg";
static const char *bootargBeta = "-spfxbeta";

//
// Plugin configuration.
//
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal,
    &bootargOff,
    1,
    &bootargDebug,
    1,
    &bootargBeta,
    1,
    KernelVersion::MountainLion,
    KernelVersion::Catalina,
    []() {
        spfx.init();
    }
};
