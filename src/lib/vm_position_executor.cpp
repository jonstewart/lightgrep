/*
 * Copyright 2024 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "vm_position_executor.h"
#include "vm_interface.h"
#include "searchhit.h"
#include "basic.h"

VmPositionExecutor::VmPositionExecutor(VmInterface& vm)
    : vm_(vm), stats_{0, 0, 0} {
}

uint64_t VmPositionExecutor::executeAtPositions(
    const std::vector<size_t>& positions,
    const uint8_t* data,
    size_t dataSize,
    uint64_t baseOffset,
    HitCallback hitFn,
    void* userData) {
    
    if (positions.empty()) {
        return baseOffset;
    }
    
    uint64_t currentOffset = baseOffset;
    
    for (size_t position : positions) {
        currentOffset = executeAtSinglePosition(position, data, dataSize, baseOffset, hitFn, userData);
        ++stats_.positionsProcessed;
        ++stats_.totalExecutions;
    }
    
    return currentOffset;
}

uint64_t VmPositionExecutor::executeAtPosition(
    size_t position,
    const uint8_t* data,
    size_t dataSize,
    uint64_t baseOffset,
    HitCallback hitFn,
    void* userData) {
    
    ++stats_.positionsProcessed;
    ++stats_.totalExecutions;
    
    return executeAtSinglePosition(position, data, dataSize, baseOffset, hitFn, userData);
}

uint64_t VmPositionExecutor::executeAtSinglePosition(
    size_t position,
    const uint8_t* data,
    size_t dataSize,
    uint64_t baseOffset,
    HitCallback hitFn,
    void* userData) {
    
    // Ensure position is within bounds
    if (position >= dataSize) {
        return baseOffset + dataSize;
    }
    
    // Calculate absolute position for VM execution
    uint64_t absolutePosition = baseOffset + position;
    
    // Execute VM starting from this specific position
    // Process a small window around the position to catch overlapping matches
    const byte* startPtr = reinterpret_cast<const byte*>(data + position);
    const byte* endPtr = reinterpret_cast<const byte*>(data + dataSize);
    
    return vm_.search(startPtr, endPtr, absolutePosition, hitFn, userData);
}

void VmPositionExecutor::resetStatistics() {
    stats_ = {0, 0, 0};
}