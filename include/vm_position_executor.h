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

#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include "basic.h"
#include "searchhit.h"

class VmInterface;

/**
 * Helper class for executing VM threads at specific positions found by NEON scanning.
 * Manages position-based execution to avoid byte-by-byte processing overhead.
 */
class VmPositionExecutor {
public:
    explicit VmPositionExecutor(VmInterface& vm);
    
    // Execute VM threads at specified positions within data chunk
    // Returns updated offset after processing all positions
    uint64_t executeAtPositions(
        const std::vector<size_t>& positions,
        const uint8_t* data,
        size_t dataSize,
        uint64_t baseOffset,
        HitCallback hitFn,
        void* userData
    );
    
    // Execute VM threads at single position (optimized path)
    uint64_t executeAtPosition(
        size_t position,
        const uint8_t* data,
        size_t dataSize,
        uint64_t baseOffset,
        HitCallback hitFn,
        void* userData
    );
    
    // Get execution statistics for performance analysis
    struct Statistics {
        size_t positionsProcessed;
        size_t hitsFound;
        size_t totalExecutions;
    };
    
    const Statistics& getStatistics() const { return stats_; }
    void resetStatistics();

private:
    VmInterface& vm_;
    Statistics stats_;
    
    // Internal execution helper
    uint64_t executeAtSinglePosition(
        size_t position,
        const uint8_t* data,
        size_t dataSize,
        uint64_t baseOffset,
        HitCallback hitFn,
        void* userData
    );
};