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

#ifndef kern_spfx_hpp
#define kern_spfx_hpp

#include <Headers/kern_api.hpp>
#include <Headers/kern_file.hpp>

#define SPFX_PLUGIN     "SPFX"

#define SECTION_ACTIVE  1

//
// Processor info struct from AppleSystemInfo.
//
typedef struct {
    uint32_t    MajorType;
    uint32_t    MinorType;
    uint32_t    NumberOfCores;
    uintptr_t   MarketingNameOffset;
    uintptr_t   TechnicalNameOffset;
} AsiProcessorInfo;

typedef struct {
    MachInfo    *MachInfo;
    uint8_t     *FileBuffer;
    
    uint8_t     *Buffer;
    size_t      Size;
} spfx_binary;

class SPFX {
public:
    void init();
    void deinit();
    
private:
    const char *bootargNoMemFix                     = "-spfxnomemfix";
    const char *bootargHideSerial                   = "-spfxhideserial";
    
    //
    // Paths.
    //
    const char *binPathSystemInformationPreCatalina = "/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
    const char *binPathSystemInformationCatalina    = "/System/Applications/Utilities/System Information.app/Contents/MacOS/System Information";
    const char *binPathSystemInformation            =
        (getKernelVersion() >= KernelVersion::Catalina) ? binPathSystemInformationCatalina : binPathSystemInformationPreCatalina;
    
    const char *binPathAppleSystemInfo              = "/System/Library/PrivateFrameworks/AppleSystemInfo.framework/Versions/A/AppleSystemInfo";
    const char *binPathSPMemoryReporter             = "/System/Library/SystemProfiler/SPMemoryReporter.spreporter/Contents/MacOS/SPMemoryReporter";
    const char *binPathSPPlatformReporter           = "/System/Library/SystemProfiler/SPPlatformReporter.spreporter/Contents/MacOS/SPPlatformReporter";
    
    //
    // Patch vectors.
    //
    evector<UserPatcher::BinaryModPatch> *patchesAppleSystemInfo    = new evector<UserPatcher::BinaryModPatch>();
    evector<UserPatcher::BinaryModPatch> *patchesSPMemoryReporter   = new evector<UserPatcher::BinaryModPatch>();
    evector<UserPatcher::BinaryModPatch> *patchesSPPlatformReporter = new evector<UserPatcher::BinaryModPatch>();
    evector<UserPatcher::BinaryModPatch> *patchesSystemInformation  = new evector<UserPatcher::BinaryModPatch>();

    evector<UserPatcher::BinaryModInfo> *binaryModInfo              = new evector<UserPatcher::BinaryModInfo>();
    
    UserPatcher::ProcInfo procInfo = { binPathSystemInformation, static_cast<uint32_t>(strlen(binPathSystemInformation)), 1 };

    bool createBinary(const char *binPath, spfx_binary *binary);
    void freeBinary (spfx_binary *binary);
    

    void copyMem(void *dst, const void *src, size_t length);
    void buildPatches(KernelPatcher &patcher);
    
    bool patchMemoryUpgradability(spfx_binary *binSPMemoryReporter, spfx_binary *binSystemInformation);
    bool patchCPUName(spfx_binary *binAppleSystemInfo, spfx_binary *binSPPlatformReporter);
    bool patchSerial(spfx_binary *binAppleSystemInfo, spfx_binary *binSPPlatformReporter);
    
};

#endif /* kern_spfx_hpp */
