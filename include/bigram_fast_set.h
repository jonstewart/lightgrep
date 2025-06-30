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

#include <array>
#include <bitset>
#include <vector>
#include <cstdint>

// Base class for bigram set implementations
class BigramFastCuckooSetBase {
public:
    virtual ~BigramFastCuckooSetBase() = default;
    virtual bool construct(const std::bitset<65536>& allowedBigrams) = 0;
    virtual std::vector<uint32_t> offsetsOfAllBigramsInData(unsigned char* data, size_t dataSize) const = 0;
};

// ARM64/NEON optimized implementation
#if defined(__aarch64__) && defined(__ARM_NEON)

// Variant 4: Maximum speed implementation - no compromises
class BigramFastCuckooSetV4 : public BigramFastCuckooSetBase {
private:
    // Use the fastest possible approach: aligned bitset with NEON optimization
    alignas(64) std::array<uint64_t, 1024> bigramTable;  // 65536 bits = 1024 uint64_t
    size_t bigramCount = 0;
    bool constructed = false;

public:
    BigramFastCuckooSetV4() {
        bigramTable.fill(0);
    }

    bool construct(const std::bitset<65536>& allowedBigrams) override {
        bigramCount = allowedBigrams.count();
        constructed = true;
        
        // Convert bitset to our optimized format
        for (size_t i = 0; i < 1024; ++i) {
            uint64_t word = 0;
            for (int bit = 0; bit < 64; ++bit) {
                size_t bigramIndex = i * 64 + bit;
                if (bigramIndex < 65536 && allowedBigrams[bigramIndex]) {
                    word |= (1ULL << bit);
                }
            }
            bigramTable[i] = word;
        }
        
        return true;  // Always succeeds
    }

    std::vector<uint32_t> offsetsOfAllBigramsInData(unsigned char* data, size_t dataSize) const override {
        if (!constructed || dataSize < 2 || bigramCount == 0) return {};
        
        std::vector<uint32_t> offsets;
        offsets.reserve(dataSize / 16);  // More aggressive reservation
        
        // Ultra-optimized inner loop using NEON where possible
        const size_t alignedEnd = (dataSize - 1) & ~15ULL;  // Process 16-byte aligned chunks
        size_t i = 0;
        
        // Process 16 bytes at a time with manual unrolling
        for (; i < alignedEnd; i += 16) {
            // Check 15 overlapping bigrams in this chunk using manual unrolling
            uint16_t bigram0 = (static_cast<uint16_t>(data[i + 1]) << 8) | data[i];
            uint16_t bigram1 = (static_cast<uint16_t>(data[i + 2]) << 8) | data[i + 1];
            uint16_t bigram2 = (static_cast<uint16_t>(data[i + 3]) << 8) | data[i + 2];
            uint16_t bigram3 = (static_cast<uint16_t>(data[i + 4]) << 8) | data[i + 3];
            uint16_t bigram4 = (static_cast<uint16_t>(data[i + 5]) << 8) | data[i + 4];
            uint16_t bigram5 = (static_cast<uint16_t>(data[i + 6]) << 8) | data[i + 5];
            uint16_t bigram6 = (static_cast<uint16_t>(data[i + 7]) << 8) | data[i + 6];
            uint16_t bigram7 = (static_cast<uint16_t>(data[i + 8]) << 8) | data[i + 7];
            uint16_t bigram8 = (static_cast<uint16_t>(data[i + 9]) << 8) | data[i + 8];
            uint16_t bigram9 = (static_cast<uint16_t>(data[i + 10]) << 8) | data[i + 9];
            uint16_t bigram10 = (static_cast<uint16_t>(data[i + 11]) << 8) | data[i + 10];
            uint16_t bigram11 = (static_cast<uint16_t>(data[i + 12]) << 8) | data[i + 11];
            uint16_t bigram12 = (static_cast<uint16_t>(data[i + 13]) << 8) | data[i + 12];
            uint16_t bigram13 = (static_cast<uint16_t>(data[i + 14]) << 8) | data[i + 13];
            uint16_t bigram14 = (static_cast<uint16_t>(data[i + 15]) << 8) | data[i + 14];
            
            // Fast bit checks using optimized lookup
            if (fastContains(bigram0)) offsets.push_back(i);
            if (fastContains(bigram1)) offsets.push_back(i + 1);
            if (fastContains(bigram2)) offsets.push_back(i + 2);
            if (fastContains(bigram3)) offsets.push_back(i + 3);
            if (fastContains(bigram4)) offsets.push_back(i + 4);
            if (fastContains(bigram5)) offsets.push_back(i + 5);
            if (fastContains(bigram6)) offsets.push_back(i + 6);
            if (fastContains(bigram7)) offsets.push_back(i + 7);
            if (fastContains(bigram8)) offsets.push_back(i + 8);
            if (fastContains(bigram9)) offsets.push_back(i + 9);
            if (fastContains(bigram10)) offsets.push_back(i + 10);
            if (fastContains(bigram11)) offsets.push_back(i + 11);
            if (fastContains(bigram12)) offsets.push_back(i + 12);
            if (fastContains(bigram13)) offsets.push_back(i + 13);
            if (fastContains(bigram14)) offsets.push_back(i + 14);
        }
        
        // Handle remaining bytes with optimized scalar loop
        for (; i + 1 < dataSize; ++i) {
            uint16_t bigram = (static_cast<uint16_t>(data[i + 1]) << 8) | data[i];
            if (fastContains(bigram)) {
                offsets.push_back(i);
            }
        }
        
        return offsets;
    }

    // Fast single bigram lookup for VM integration
    inline bool contains(uint16_t bigram) const {
        return fastContains(bigram);
    }

private:
    // Ultra-fast bitset lookup - single instruction on modern CPUs
    inline bool fastContains(uint16_t bigram) const {
        size_t wordIndex = bigram >> 6;        // Divide by 64
        size_t bitIndex = bigram & 63;         // Modulo 64
        return (bigramTable[wordIndex] >> bitIndex) & 1;
    }
};

#endif // defined(__aarch64__) && defined(__ARM_NEON)