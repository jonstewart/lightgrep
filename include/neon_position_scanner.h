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

#include "match_position_collector.h"
#include <bitset>
#include <vector>
#include <cstdint>
#include <cstddef>

#ifdef __aarch64__
#include <arm_neon.h>
#endif

/**
 * NEON-optimized scanner that finds bigram match positions within data chunks.
 * Uses SIMD table lookups to efficiently scan large buffers and collect
 * exact positions where matches occur, rather than just indicating presence.
 */
class NeonPositionScanner {
public:
    static constexpr size_t CHUNK_SIZE = 64;  // Process 64-byte chunks for optimal NEON usage
    static constexpr size_t DEFAULT_MAX_BIGRAMS = 256;
    
    explicit NeonPositionScanner(const std::bitset<65536>& filter, size_t maxBigrams = DEFAULT_MAX_BIGRAMS);
    
    // Check if this scanner is applicable for the given bigram set size
    bool isApplicable() const { return applicable_; }
    
    // Get number of bigrams this scanner handles
    size_t getBigramCount() const { return bigramCount_; }
    
    // Scan a data buffer and collect all match positions
    void scanPositions(const uint8_t* data, size_t dataSize, int filterOffset, 
                      MatchPositionCollector& collector) const;
    
    // Scan a chunk and return positions within that chunk (relative to chunk start)
    void scanChunk(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                   MatchPositionCollector& collector) const;

private:
    bool applicable_;
    size_t bigramCount_;
    
    // Scalar bitset lookup for comparison/validation
    std::bitset<256> highByteSet_, lowByteSet_;
    
#ifdef __aarch64__
    // NEON-specific implementation
    void scanChunkNEON(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                       MatchPositionCollector& collector) const;
    
    // Optimized lookup tables for NEON TBL instructions
    alignas(16) uint8_t lookupTable_[16];
    alignas(16) uint8_t maskTable_[16];
    
    // Compact representation for efficient NEON processing
    std::vector<uint16_t> targetBigrams_;
#endif
    
    // Scalar fallback implementation
    void scanChunkScalar(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                        MatchPositionCollector& collector) const;
    
    // Helper to validate a potential bigram match
    bool isMatchingBigram(uint16_t bigram) const;
};