// Test: Max Alloc
// Copyright (c) 2025 University of Virginia
// This file is licensed under the MIT License.
// See the LICENSE file in the root of this repository for more details.

#include "libpimeval.h"
#include <iostream>
#include <cassert>

bool testMaxAlloc(PimDeviceEnum deviceType)
{
  unsigned numRanks = 2;
  unsigned numBankPerRank = 2;
  unsigned numSubarrayPerBank = 8;
  unsigned numRows = 1024;
  unsigned numCols = 8192;

  PimStatus status = pimCreateDevice(deviceType, numRanks, numBankPerRank, numSubarrayPerBank, numRows, numCols);
  assert(status == PIM_OK);

  constexpr uint64_t bitsPerElement = 8;

  PimDeviceProperties deviceProp;
  status = pimGetDeviceProperties(&deviceProp);
  assert(status == PIM_OK);

  // Maximum number of objects that can be associated with each other
  const uint64_t numAssociable = deviceProp.isHLayoutDevice ? deviceProp.numRowPerCore : deviceProp.numRowPerCore/bitsPerElement;

  // Allocate exactly enough elements to fill one region
  const uint64_t numElements = deviceProp.isHLayoutDevice ? deviceProp.numColPerSubarray/bitsPerElement : deviceProp.numColPerSubarray;

  const uint64_t coresToTest = deviceProp.numPIMCores;
  std::vector<std::vector<PimObjId>> pimObjs(coresToTest, std::vector<PimObjId>(numAssociable));

  for(uint64_t coreNum=0; coreNum<coresToTest; ++coreNum) {
    pimObjs[coreNum][0] = pimAlloc(PIM_ALLOC_AUTO, numElements, PIM_UINT8);
    if(pimObjs[coreNum][0] == -1) {
        std::cout << "ERROR: pimAlloc failed on core " << coreNum << std::endl;
    }
    assert(pimObjs[coreNum][0] != -1);

    for(uint64_t i=1; i<numAssociable; ++i) {
      pimObjs[coreNum][i] = pimAllocAssociated(pimObjs[coreNum][0], PIM_UINT8);
      assert(pimObjs[coreNum][i] != -1);
    }

    // Free Test
    status = pimFree(pimObjs[coreNum][0]);
    assert(status == PIM_OK);

    pimObjs[coreNum][0] = pimAllocAssociated(pimObjs[coreNum][1], PIM_UINT8);
    assert(pimObjs[coreNum][0] != -1);
  }

  pimShowStats();
  pimResetStats();
  pimDeleteDevice();
  return true;
}

int main()
{
  std::cout << "INFO: Max Alloc Test" << std::endl;

  bool ok = true;
  ok &= testMaxAlloc(PIM_DEVICE_BITSIMD_V);
  std::cout << "Suceeded for BITSiMD-V" << std::endl;
  ok &= testMaxAlloc(PIM_DEVICE_BITSIMD_V_AP);
  std::cout << "Suceeded for BITSiMD-V-AP" << std::endl;
  ok &= testMaxAlloc(PIM_DEVICE_BANK_LEVEL);
  std::cout << "Suceeded for Bank-Level PIM" << std::endl;
  ok &= testMaxAlloc(PIM_DEVICE_FULCRUM);
  std::cout << "Suceeded for Fulcrum PIM" << std::endl;
  std::cout << (ok ? "ALL PASSED!" : "FAILED!") << std::endl;

  return 0;
}