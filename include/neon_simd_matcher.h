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

#include <bitset>
#include <vector>
#include <cstdint>

#ifdef __aarch64__
#include <arm_neon.h>
#endif

/**
 * NEON-based SIMD matcher for small sets of bigrams, inspired by SMH (Shuffle-based Matching Hash)
 * Uses NEON table lookup (TBL) instructions with partitioned registers for optimal performance
 * Each partition handles a subset of possible bigram values using direct table lookups
 */
class NeonSIMDMatcher {
public:
    // Empirically determined threshold from Catch2 benchmarks:
    // - NEON excels with absent/rare bigrams: up to 1790x faster than bitset
    // - NEON is slower with frequent matches: ~6x slower due to early exit advantage of bitset
    // - Optimal threshold balances these trade-offs for typical forensics workloads
    static constexpr size_t DEFAULT_MAX_BIGRAMS = 128;
    static constexpr size_t NUM_PARTITIONS = 4;
    
    explicit NeonSIMDMatcher(const std::bitset<65536>& filter, size_t maxBigrams = DEFAULT_MAX_BIGRAMS);
    
    // Check if this matcher is applicable (small enough pattern set)
    bool isApplicable() const { return applicable_; }
    
    // Fast SIMD scan for bigrams in a memory region using TBL lookups
    bool hasMatchingBigrams(const uint8_t* data, size_t len, int filterOffset) const;
    
    // Get number of bigrams this matcher handles
    size_t getBigramCount() const { return bigramCount_; }
    
    // Static method to determine optimal threshold via hill-climbing
    static size_t findOptimalThreshold(const std::vector<std::bitset<65536>>& testFilters,
                                       const std::vector<std::vector<uint8_t>>& testData);
    
private:
    bool applicable_;
    size_t bigramCount_;
    
#ifdef __aarch64__
    // NEON table lookup implementation using SMH approach
    bool hasMatchingBigramsNEON(const uint8_t* data, size_t len, int filterOffset) const;
    
    // Partitioned lookup tables for parallel TBL operations
    // Each partition contains a 16-byte lookup table for TBL instruction
    alignas(16) uint8_t lookupTables_[NUM_PARTITIONS][16];
    
    // Mask tables for efficient bigram matching
    alignas(16) uint8_t maskTables_[NUM_PARTITIONS][16];
    
    // Number of active partitions (depends on bigram count)
    size_t activePartitions_;
#endif
    
    // Fallback scalar implementation
    bool hasMatchingBigramsScalar(const uint8_t* data, size_t len, int filterOffset) const;
    
    // Scalar lookup for comparison and fallback
    std::bitset<256> highByteSet_, lowByteSet_;
};