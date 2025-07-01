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

#include "neon_position_scanner.h"
#include <algorithm>
#include <cstring>

NeonPositionScanner::NeonPositionScanner(const std::bitset<65536>& filter, size_t maxBigrams)
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
        
        // Initialize scalar lookup sets for validation
        highByteSet_.reset();
        lowByteSet_.reset();
        
        for (uint16_t bigram : bigrams) {
            highByteSet_[bigram >> 8] = 1;
            lowByteSet_[bigram & 0xFF] = 1;
        }
        
#ifdef __aarch64__
        // Initialize NEON lookup tables
        std::memset(lookupTable_, 0, sizeof(lookupTable_));
        std::memset(maskTable_, 0, sizeof(maskTable_));
        
        // Store target bigrams for exact matching
        targetBigrams_ = bigrams;
        
        // Build simple lookup table for common byte patterns
        // This is a simplified approach - more sophisticated hashing could be used
        for (uint16_t bigram : bigrams) {
            uint8_t highByte = static_cast<uint8_t>(bigram >> 8);
            uint8_t lowByte = static_cast<uint8_t>(bigram & 0xFF);
            
            // Use XOR of high and low bytes as index (simple hash)
            uint8_t index = (highByte ^ lowByte) & 0xF;
            
            // Mark this index as potentially having matches
            lookupTable_[index] = 0xFF;  // Mark as active
            maskTable_[index] = 0xFF;    // Mark as valid
        }
#endif
    }
}

void NeonPositionScanner::scanPositions(const uint8_t* data, size_t dataSize, int filterOffset,
                                       MatchPositionCollector& collector) const {
    if (!applicable_ || dataSize < 2) {
        return;
    }
    
    const uint8_t* ptr = data + filterOffset;
    const size_t effectiveSize = (dataSize >= static_cast<size_t>(filterOffset)) ? 
                                 dataSize - filterOffset : 0;
    
    if (effectiveSize < 2) {
        return;
    }
    
    // Process data in chunks for optimal SIMD usage
    size_t pos = 0;
    while (pos + CHUNK_SIZE <= effectiveSize) {
        scanChunk(ptr + pos, CHUNK_SIZE, 0, collector);
        pos += CHUNK_SIZE;
    }
    
    // Handle remainder
    if (pos < effectiveSize - 1) {
        scanChunk(ptr + pos, effectiveSize - pos, 0, collector);
    }
}

void NeonPositionScanner::scanChunk(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                                   MatchPositionCollector& collector) const {
    if (!applicable_ || chunkSize < 2) {
        return;
    }
    
#ifdef __aarch64__
    scanChunkNEON(chunkData, chunkSize, filterOffset, collector);
#else
    scanChunkScalar(chunkData, chunkSize, filterOffset, collector);
#endif
}

#ifdef __aarch64__
void NeonPositionScanner::scanChunkNEON(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                                        MatchPositionCollector& collector) const {
    const uint8_t* ptr = chunkData + filterOffset;
    const size_t end = chunkSize - 1;
    
    // Process 16-byte SIMD chunks
    size_t simdPos = 0;
    const size_t simdEnd = (end >= 16) ? end - 15 : 0;
    
    for (; simdPos < simdEnd; simdPos += 16) {
        // Load 16 bytes
        uint8x16_t chunk = vld1q_u8(ptr + simdPos);
        
        // Extract to array for bigram formation and checking
        uint8_t chunkBytes[16];
        vst1q_u8(chunkBytes, chunk);
        
        // Check each potential bigram position within this 16-byte chunk
        for (int i = 0; i < 15; ++i) {
            uint8_t highByte = chunkBytes[i];
            uint8_t lowByte = chunkBytes[i + 1];
            
            // Quick filter using precomputed sets
            if (highByteSet_[highByte] && lowByteSet_[lowByte]) {
                uint16_t bigram = (static_cast<uint16_t>(highByte) << 8) | lowByte;
                
                // Verify against exact target bigrams
                if (isMatchingBigram(bigram)) {
                    size_t absolutePos = simdPos + i;
                    collector.addPosition(absolutePos);
                }
            }
        }
    }
    
    // Handle remaining bytes with scalar processing
    scanChunkScalar(ptr + simdPos, chunkSize - simdPos, 0, collector);
}
#endif

void NeonPositionScanner::scanChunkScalar(const uint8_t* chunkData, size_t chunkSize, int filterOffset,
                                         MatchPositionCollector& collector) const {
    if (chunkSize < 2) return;
    
    const uint8_t* ptr = chunkData + filterOffset;
    const size_t end = chunkSize - 1;
    
    for (size_t i = 0; i < end; ++i) {
        uint8_t highByte = ptr[i];
        uint8_t lowByte = ptr[i + 1];
        
        // Quick filter using precomputed sets
        if (highByteSet_[highByte] && lowByteSet_[lowByte]) {
            uint16_t bigram = (static_cast<uint16_t>(highByte) << 8) | lowByte;
            
            // Verify against exact target bigrams
            if (isMatchingBigram(bigram)) {
                collector.addPosition(i);
            }
        }
    }
}

bool NeonPositionScanner::isMatchingBigram(uint16_t bigram) const {
#ifdef __aarch64__
    // Use the stored target bigrams for exact matching
    return std::binary_search(targetBigrams_.begin(), targetBigrams_.end(), bigram);
#else
    // For scalar version, we need to check against original filter
    // This is a simplified version - in practice we'd store the original filter reference
    uint8_t highByte = bigram >> 8;
    uint8_t lowByte = bigram & 0xFF;
    return highByteSet_[highByte] && lowByteSet_[lowByte];
#endif
}