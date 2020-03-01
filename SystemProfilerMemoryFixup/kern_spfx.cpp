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

void SPFX::init() {
    DBGLOG(SPFX_PLUGIN, "start");
    lilu.onPatcherLoad([](void *user, KernelPatcher &patcher) {
        static_cast<SPFX *>(user)->buildPatches(patcher);
    }, this);
}

void SPFX::deinit() {
}

bool SPFX::createBinary(const char *binPath, spfx_binary *binary) {
    MachInfo *machInfo = MachInfo::create();
    if (machInfo == NULL) {
        SYSLOG(SPFX_PLUGIN, "Failed to create mach info for %s", binPath);
        return false;
    }
    
    if (machInfo->init(&binPath) != KERN_SUCCESS
        || machInfo->setRunningAddresses(0) != KERN_SUCCESS) {
        SYSLOG(SPFX_PLUGIN, "Failed to init mach info for %s", binPath);
        machInfo->deinit();
        MachInfo::deleter(machInfo);
        return false;
    }
    
    size_t bufferSize;
    uint8_t *buffer = FileIO::readFileToBuffer(binPath, bufferSize);
    if (buffer == NULL) {
        SYSLOG(SPFX_PLUGIN, "Failed to read data for %s", binPath);
        machInfo->deinit();
        MachInfo::deleter(machInfo);
        return false;
    }
    
    binary->MachInfo    = machInfo;
    binary->FileBuffer  = buffer;
    binary->Buffer      = buffer + machInfo->getFatOffset();
    binary->Size        = bufferSize - machInfo->getFatOffset();
    return true;
}

void SPFX::freeBinary (spfx_binary *binary) {
    if (binary->FileBuffer != NULL) {
        Buffer::deleter(binary->FileBuffer);
    }
    if (binary->MachInfo != NULL) {
        binary->MachInfo->deinit();
        MachInfo::deleter(binary->MachInfo);
    }
    memset(binary, 0, sizeof (spfx_binary));
}

void SPFX::copyMem(void *dst, const void *src, size_t length) {
    for (int index = 0; index < length; index++) {
        ((uint8_t*) dst)[index] = ((uint8_t*) src)[index];
    }
}

void SPFX::buildPatches(KernelPatcher &patcher) {
    spfx_binary binAppleSystemInfo = { };
    spfx_binary binSPPlatformReporter = { };
    spfx_binary binSPMemoryReporter = { };
    spfx_binary binSystemInformation = { };
    bool failed = false;
    
    failed |= !createBinary(binPathAppleSystemInfo, &binAppleSystemInfo);
    failed |= !createBinary(binPathSPPlatformReporter, &binSPPlatformReporter);
    failed |= !createBinary(binPathSPMemoryReporter, &binSPMemoryReporter);
    failed |= !createBinary(binPathSystemInformation, &binSystemInformation);
    if (failed) {
        freeBinary(&binAppleSystemInfo);
        freeBinary(&binSPPlatformReporter);
        freeBinary(&binSPMemoryReporter);
        freeBinary(&binSystemInformation);
        return;
    }
    
    patchMemoryUpgradability(&binSPMemoryReporter, &binSystemInformation, false);
    patchCPUName(&binAppleSystemInfo, &binSPPlatformReporter);
    patchSerial(&binAppleSystemInfo, &binSPPlatformReporter);
    
    //
    // Add applicable patches.
    //
    if (patchesAppleSystemInfo->size() > 0) {
        binaryModInfo->push_back({ binPathAppleSystemInfo,
            patchesAppleSystemInfo->data(), patchesAppleSystemInfo->size() });
    }
    if (patchesSPMemoryReporter->size() > 0) {
        binaryModInfo->push_back({ binPathSPMemoryReporter,
            patchesSPMemoryReporter->data(), patchesSPMemoryReporter->size() });
    }
    if (patchesSPPlatformReporter->size() > 0) {
        binaryModInfo->push_back({ binPathSPPlatformReporter,
            patchesSPPlatformReporter->data(), patchesSPPlatformReporter->size() });
    }
    if (patchesSystemInformation->size() > 0) {
        binaryModInfo->push_back({ binPathSystemInformation,
            patchesSystemInformation->data(), patchesSystemInformation->size() });
    }
    
    //
    // Register patches.
    //
    if (binaryModInfo->size() == 0) {
        return;
    }
    lilu.onProcLoadForce(&procInfo, 1, nullptr, nullptr, binaryModInfo->data(), binaryModInfo->size());
}
