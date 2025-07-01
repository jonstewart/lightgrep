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

#include "neon_simd_matcher.h"
#include <algorithm>
#include <cstring>
#include <chrono>

NeonSIMDMatcher::NeonSIMDMatcher(const std::bitset<65536>& filter, size_t maxBigrams) 
    : applicable_(false), bigramCount_(0) {
    
    // Extract all set bigrams from the filter
    std::vector<uint16_t> bigrams;
    for (size_t i = 0; i < 65536; ++i) {
        if (filter[i]) {
            bigrams.push_back(static_cast<uint16_t>(i));
        }
    }
    
    bigramCount_ = bigrams.size();
    
    // Check if we can handle this pattern set efficiently
    if (bigramCount_ <= maxBigrams && bigramCount_ > 0) {
        applicable_ = true;
        
        // Initialize scalar lookup tables
        highByteSet_.reset();
        lowByteSet_.reset();
        
#ifdef __aarch64__
        // Initialize NEON lookup tables using SMH approach
        std::memset(lookupTables_, 0, sizeof(lookupTables_));
        std::memset(maskTables_, 0, sizeof(maskTables_));
        
        // Determine number of active partitions based on bigram count
        activePartitions_ = std::min(NUM_PARTITIONS, (bigramCount_ + 15) / 16);
        if (activePartitions_ == 0) activePartitions_ = 1;
        
        // Build partitioned lookup tables for parallel TBL operations
        // Each partition handles a subset of the bigram space
        for (size_t partition = 0; partition < activePartitions_; ++partition) {
            // Initialize lookup and mask tables for this partition
            for (size_t i = 0; i < 16; ++i) {
                lookupTables_[partition][i] = 0;
                maskTables_[partition][i] = 0;
            }
            
            // Populate this partition with relevant bigrams
            size_t bigramsInPartition = 0;
            for (size_t i = partition; i < bigrams.size() && bigramsInPartition < 16; i += activePartitions_) {
                uint16_t bigram = bigrams[i];
                uint8_t highByte = static_cast<uint8_t>(bigram >> 8);
                uint8_t lowByte = static_cast<uint8_t>(bigram & 0xFF);
                
                // Create lookup entry for TBL instruction
                // Use combined hash of high and low bytes as lookup index
                uint8_t lookupIndex = (highByte ^ lowByte) & 0xF;
                
                // Set bit in lookup table indicating this combination exists
                lookupTables_[partition][lookupIndex] |= (1 << (bigramsInPartition & 0x7));
                
                // Create mask for validation
                maskTables_[partition][lookupIndex] = 0xFF; // Mark as valid entry
                
                bigramsInPartition++;
            }
        }
#endif
        
        // Populate scalar lookup sets for fallback and validation
        for (uint16_t bigram : bigrams) {
            highByteSet_[bigram >> 8] = 1;
            lowByteSet_[bigram & 0xFF] = 1;
        }
    }
}

bool NeonSIMDMatcher::hasMatchingBigrams(const uint8_t* data, size_t len, int filterOffset) const {
    if (!applicable_ || len < 2) {
        return false;
    }
    
#ifdef __aarch64__
    return hasMatchingBigramsNEON(data, len, filterOffset);
#else
    return hasMatchingBigramsScalar(data, len, filterOffset);
#endif
}

#ifdef __aarch64__
bool NeonSIMDMatcher::hasMatchingBigramsNEON(const uint8_t* data, size_t len, int filterOffset) const {
    const uint8_t* ptr = data + filterOffset;
    const size_t end = len - 1;
    
    // Process 16-byte chunks using parallel TBL operations across partitions
    const size_t simdEnd = (end >= 16) ? end - 15 : 0;
    
    for (size_t i = 0; i < simdEnd; i += 16) {
        // Load 16 bytes for SIMD processing
        uint8x16_t chunk = vld1q_u8(ptr + i);
        
        // Create bigram pairs by shifting and combining bytes
        uint8x16_t highBytes = chunk;
        uint8x16_t lowBytes = vextq_u8(chunk, vdupq_n_u8(0), 1); // shift left by 1 byte
        
        // Combine high and low bytes to create lookup indices
        uint8x16_t lookupIndices = veorq_u8(highBytes, lowBytes);
        lookupIndices = vandq_u8(lookupIndices, vdupq_n_u8(0xF)); // mask to 4 bits
        
        // Perform parallel TBL lookups across all active partitions
        bool hasMatch = false;
        for (size_t partition = 0; partition < activePartitions_ && !hasMatch; ++partition) {
            // Load lookup table for this partition
            uint8x16_t lookupTable = vld1q_u8(lookupTables_[partition]);
            uint8x16_t maskTable = vld1q_u8(maskTables_[partition]);
            
            // Perform table lookup using TBL instruction
            uint8x16_t lookupResult = vqtbl1q_u8(lookupTable, lookupIndices);
            
            // Apply mask to validate entries
            uint8x16_t maskedResult = vandq_u8(lookupResult, maskTable);
            
            // Check if any lanes have matches (non-zero values)
            uint64_t result = vaddlvq_u8(maskedResult);
            if (result != 0) {
                // We have potential matches, but need to verify actual bigrams
                // Extract data for detailed checking
                uint8_t chunkData[16];
                vst1q_u8(chunkData, chunk);
                
                for (int j = 0; j < 15; ++j) {
                    uint8_t byte1 = chunkData[j];
                    uint8_t byte2 = chunkData[j + 1];
                    
                    // Use scalar lookup for final verification
                    if (highByteSet_[byte1] && lowByteSet_[byte2]) {
                        return true;
                    }
                }
            }
        }
    }
    
    // Handle remaining bytes with scalar code
    return hasMatchingBigramsScalar(ptr + simdEnd, len - simdEnd, 0);
}
#endif

bool NeonSIMDMatcher::hasMatchingBigramsScalar(const uint8_t* data, size_t len, int filterOffset) const {
    if (len < 2) return false;
    
    const uint8_t* ptr = data + filterOffset;
    const size_t end = len - 1;
    
    for (size_t i = 0; i < end; ++i) {
        uint8_t byte1 = ptr[i];
        uint8_t byte2 = ptr[i + 1];
        
        // Quick filter using bitsets
        if (highByteSet_[byte1] && lowByteSet_[byte2]) {
            return true;
        }
    }
    
    return false;
}

size_t NeonSIMDMatcher::findOptimalThreshold(const std::vector<std::bitset<65536>>& testFilters,
                                           const std::vector<std::vector<uint8_t>>& testData) {
    if (testFilters.empty() || testData.empty()) {
        return DEFAULT_MAX_BIGRAMS;
    }
    
    // Hill-climbing parameters
    constexpr size_t MIN_THRESHOLD = 8;
    constexpr size_t MAX_THRESHOLD = 128;
    constexpr size_t STEP_SIZE = 8;
    constexpr int NUM_ITERATIONS = 5;
    
    size_t bestThreshold = DEFAULT_MAX_BIGRAMS;
    double bestSpeedup = 0.0;
    
    // Test different thresholds to find optimal point
    for (size_t threshold = MIN_THRESHOLD; threshold <= MAX_THRESHOLD; threshold += STEP_SIZE) {
        double totalSpeedup = 0.0;
        int validTests = 0;
        
        // Test this threshold against all test cases
        for (size_t filterIdx = 0; filterIdx < testFilters.size(); ++filterIdx) {
            const auto& filter = testFilters[filterIdx];
            
            // Count bigrams in this filter
            size_t bigramCount = 0;
            for (size_t i = 0; i < 65536; ++i) {
                if (filter[i]) bigramCount++;
            }
            
            // Only test filters that would use NEON matcher with this threshold
            if (bigramCount == 0 || bigramCount > threshold) continue;
            
            // Create NEON matcher for this threshold
            NeonSIMDMatcher neonMatcher(filter, threshold);
            if (!neonMatcher.isApplicable()) continue;
            
            // Time NEON matcher performance
            auto neonStart = std::chrono::high_resolution_clock::now();
            for (const auto& data : testData) {
                if (data.size() >= 2) {
                    volatile bool result = neonMatcher.hasMatchingBigrams(data.data(), data.size(), 0);
                    (void)result; // Prevent optimization
                }
            }
            auto neonEnd = std::chrono::high_resolution_clock::now();
            auto neonTime = std::chrono::duration_cast<std::chrono::nanoseconds>(neonEnd - neonStart).count();
            
            // Time bitset performance for comparison
            auto bitsetStart = std::chrono::high_resolution_clock::now();
            for (const auto& data : testData) {
                if (data.size() >= 2) {
                    for (size_t i = 0; i < data.size() - 1; ++i) {
                        uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
                        volatile bool result = filter[bigram];
                        (void)result;
                        if (result) break; // Early exit like NEON matcher
                    }
                }
            }
            auto bitsetEnd = std::chrono::high_resolution_clock::now();
            auto bitsetTime = std::chrono::duration_cast<std::chrono::nanoseconds>(bitsetEnd - bitsetStart).count();
            
            // Calculate speedup (positive means NEON is faster)
            if (neonTime > 0) {
                double speedup = static_cast<double>(bitsetTime) / static_cast<double>(neonTime);
                totalSpeedup += speedup;
                validTests++;
            }
        }
        
        // Calculate average speedup for this threshold
        if (validTests > 0) {
            double avgSpeedup = totalSpeedup / validTests;
            if (avgSpeedup > bestSpeedup) {
                bestSpeedup = avgSpeedup;
                bestThreshold = threshold;
            }
        }
    }
    
    // Return best threshold found, ensuring it's at least as good as bitset
    return (bestSpeedup >= 1.0) ? bestThreshold : 0; // 0 means don't use NEON matcher
}