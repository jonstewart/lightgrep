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

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include "neon_simd_matcher.h"

#include <bitset>
#include <vector>
#include <random>
#include <fstream>
#include <algorithm>
#include <set>

// Test data size for consistent benchmarking
constexpr size_t TEST_DATA_SIZE = 16 * 1024; // 16KB

class BenchmarkDataGenerator {
public:
    static std::vector<uint8_t> generateRandomData() {
        std::vector<uint8_t> data(TEST_DATA_SIZE);
        std::random_device rd;
        std::mt19937 gen(42); // Fixed seed for reproducibility
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (auto& byte : data) {
            byte = dis(gen);
        }
        return data;
    }
    
    static std::vector<uint8_t> loadTwainCorpus() {
        std::ifstream file("pytest/corpora/marktwainworks.txt", std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open Twain corpus");
        }
        
        // Seek to offset well into the file (5MB in)
        file.seekg(5 * 1024 * 1024);
        
        std::vector<uint8_t> data(TEST_DATA_SIZE);
        file.read(reinterpret_cast<char*>(data.data()), TEST_DATA_SIZE);
        
        if (file.gcount() != TEST_DATA_SIZE) {
            throw std::runtime_error("Could not read enough data from Twain corpus");
        }
        
        return data;
    }
    
    static std::vector<uint8_t> generateStructuredData() {
        // Simulate a small PDF with compressed data
        std::vector<uint8_t> data;
        data.reserve(TEST_DATA_SIZE);
        
        // PDF header-like structure
        std::string header = "%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n";
        data.insert(data.end(), header.begin(), header.end());
        
        // Add some repetitive binary patterns (like compressed data)
        std::random_device rd;
        std::mt19937 gen(123); // Fixed seed for reproducibility
        
        while (data.size() < TEST_DATA_SIZE) {
            // Add structured patterns with some randomness
            for (int pattern = 0; pattern < 256 && data.size() < TEST_DATA_SIZE; ++pattern) {
                // Repeat patterns with variations
                for (int repeat = 0; repeat < 8 && data.size() < TEST_DATA_SIZE; ++repeat) {
                    data.push_back(static_cast<uint8_t>(pattern));
                    if (data.size() < TEST_DATA_SIZE) {
                        data.push_back(static_cast<uint8_t>(gen() % 256));
                    }
                }
            }
        }
        
        data.resize(TEST_DATA_SIZE);
        return data;
    }
    
    static std::vector<uint16_t> extractBigramsFromData(const std::vector<uint8_t>& data, size_t count) {
        std::set<uint16_t> bigramSet;
        
        // Extract actual bigrams from the data
        for (size_t i = 0; i < data.size() - 1 && bigramSet.size() < count; ++i) {
            uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
            bigramSet.insert(bigram);
        }
        
        return std::vector<uint16_t>(bigramSet.begin(), bigramSet.end());
    }
    
    static std::vector<uint16_t> generateAbsentBigrams(const std::vector<uint8_t>& data, size_t count) {
        // Create set of existing bigrams
        std::set<uint16_t> existingBigrams;
        for (size_t i = 0; i < data.size() - 1; ++i) {
            uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
            existingBigrams.insert(bigram);
        }
        
        // Generate bigrams that don't exist in the data
        std::vector<uint16_t> absentBigrams;
        std::random_device rd;
        std::mt19937 gen(456); // Fixed seed
        std::uniform_int_distribution<uint16_t> dis(0, 65535);
        
        while (absentBigrams.size() < count) {
            uint16_t candidate = dis(gen);
            if (existingBigrams.find(candidate) == existingBigrams.end()) {
                absentBigrams.push_back(candidate);
            }
        }
        
        return absentBigrams;
    }
    
    static std::vector<uint16_t> generateMixedBigrams(const std::vector<uint8_t>& data, size_t count) {
        auto present = extractBigramsFromData(data, count / 2);
        auto absent = generateAbsentBigrams(data, count - present.size());
        
        std::vector<uint16_t> mixed;
        mixed.insert(mixed.end(), present.begin(), present.end());
        mixed.insert(mixed.end(), absent.begin(), absent.end());
        
        // Shuffle to mix present and absent bigrams
        std::random_device rd;
        std::mt19937 gen(789);
        std::shuffle(mixed.begin(), mixed.end(), gen);
        
        return mixed;
    }
    
    static std::vector<uint16_t> generateRandomBigrams(size_t count) {
        std::vector<uint16_t> bigrams;
        std::random_device rd;
        std::mt19937 gen(101112); // Fixed seed
        std::uniform_int_distribution<uint16_t> dis(0, 65535);
        
        std::set<uint16_t> uniqueBigrams;
        while (uniqueBigrams.size() < count) {
            uniqueBigrams.insert(dis(gen));
        }
        
        return std::vector<uint16_t>(uniqueBigrams.begin(), uniqueBigrams.end());
    }
};

template<size_t THRESHOLD>
void benchmarkNeonVsBitset(const std::vector<uint8_t>& data, 
                          const std::vector<uint16_t>& bigrams,
                          const std::string& testName) {
    
    // Create bitset filter from bigrams
    std::bitset<65536> filter;
    for (uint16_t bigram : bigrams) {
        filter[bigram] = 1;
    }
    
    // Create NEON matcher with the specified threshold
    NeonSIMDMatcher neonMatcher(filter, THRESHOLD);
    
    SECTION(testName + " - Threshold " + std::to_string(THRESHOLD) + " - " + std::to_string(bigrams.size()) + " bigrams") {
        
        // Only benchmark if NEON matcher is applicable for this threshold/bigram combination
        if (neonMatcher.isApplicable()) {
            
            BENCHMARK("NEON Matcher") {
                return neonMatcher.hasMatchingBigrams(data.data(), data.size(), 0);
            };
        }
        
        BENCHMARK("Bitset Matcher") {
            bool found = false;
            for (size_t i = 0; i < data.size() - 1 && !found; ++i) {
                uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
                found = filter[bigram];
            }
            return found;
        };
    }
}

// Helper functions for different bigram generation strategies
static std::vector<uint16_t> getBigrams(const std::vector<uint8_t>& data, const std::string& type, size_t count) {
    if (type == "Random") {
        return BenchmarkDataGenerator::generateRandomBigrams(count);
    } else if (type == "Present") {
        return BenchmarkDataGenerator::extractBigramsFromData(data, count);
    } else if (type == "Absent") {
        return BenchmarkDataGenerator::generateAbsentBigrams(data, count);
    } else if (type == "Mixed") {
        return BenchmarkDataGenerator::generateMixedBigrams(data, count);
    }
    throw std::runtime_error("Unknown bigram type: " + type);
}

static std::vector<uint8_t> getData(const std::string& type) {
    if (type == "Random") {
        return BenchmarkDataGenerator::generateRandomData();
    } else if (type == "Twain") {
        return BenchmarkDataGenerator::loadTwainCorpus();
    } else if (type == "Structured") {
        return BenchmarkDataGenerator::generateStructuredData();
    }
    throw std::runtime_error("Unknown data type: " + type);
}

// Template instantiations for different thresholds
#define INSTANTIATE_BENCHMARK(THRESHOLD, DATA_TYPE, BIGRAM_TYPE, SIZES...) \
    TEST_CASE("NEON Benchmark - " DATA_TYPE " - " BIGRAM_TYPE " - Threshold " #THRESHOLD) { \
        auto data = getData(DATA_TYPE); \
        std::vector<size_t> sizes = {SIZES}; \
        for (size_t bigramCount : sizes) { \
            if (bigramCount <= THRESHOLD) { \
                auto bigrams = getBigrams(data, BIGRAM_TYPE, bigramCount); \
                benchmarkNeonVsBitset<THRESHOLD>(data, bigrams, DATA_TYPE " " BIGRAM_TYPE); \
            } \
        } \
    }

// Random data benchmarks
INSTANTIATE_BENCHMARK(8, "Random", "Random", 4, 8)
INSTANTIATE_BENCHMARK(16, "Random", "Random", 4, 8, 12, 16)
INSTANTIATE_BENCHMARK(32, "Random", "Random", 8, 16, 24, 32)
INSTANTIATE_BENCHMARK(64, "Random", "Random", 16, 32, 48, 64)
INSTANTIATE_BENCHMARK(128, "Random", "Random", 32, 64, 96, 128)
INSTANTIATE_BENCHMARK(256, "Random", "Random", 64, 128, 192, 256)
INSTANTIATE_BENCHMARK(512, "Random", "Random", 128, 256, 384, 512)
INSTANTIATE_BENCHMARK(1024, "Random", "Random", 256, 512, 768, 1024)
INSTANTIATE_BENCHMARK(2048, "Random", "Random", 512, 1024, 1536, 2048)

// Twain corpus with present bigrams
INSTANTIATE_BENCHMARK(8, "Twain", "Present", 4, 8)
INSTANTIATE_BENCHMARK(16, "Twain", "Present", 4, 8, 12, 16)
INSTANTIATE_BENCHMARK(32, "Twain", "Present", 8, 16, 24, 32)
INSTANTIATE_BENCHMARK(64, "Twain", "Present", 16, 32, 48, 64)
INSTANTIATE_BENCHMARK(128, "Twain", "Present", 32, 64, 96, 128)
INSTANTIATE_BENCHMARK(256, "Twain", "Present", 64, 128, 192, 256)
INSTANTIATE_BENCHMARK(512, "Twain", "Present", 128, 256, 384, 512)
INSTANTIATE_BENCHMARK(1024, "Twain", "Present", 256, 512, 768, 1024)

// Twain corpus with absent bigrams (no matches)
INSTANTIATE_BENCHMARK(8, "Twain", "Absent", 4, 8)
INSTANTIATE_BENCHMARK(16, "Twain", "Absent", 4, 8, 12, 16)
INSTANTIATE_BENCHMARK(32, "Twain", "Absent", 8, 16, 24, 32)
INSTANTIATE_BENCHMARK(64, "Twain", "Absent", 16, 32, 48, 64)
INSTANTIATE_BENCHMARK(128, "Twain", "Absent", 32, 64, 96, 128)
INSTANTIATE_BENCHMARK(256, "Twain", "Absent", 64, 128, 192, 256)

// Structured data with mixed bigrams
INSTANTIATE_BENCHMARK(8, "Structured", "Mixed", 4, 8)
INSTANTIATE_BENCHMARK(16, "Structured", "Mixed", 4, 8, 12, 16)
INSTANTIATE_BENCHMARK(32, "Structured", "Mixed", 8, 16, 24, 32)
INSTANTIATE_BENCHMARK(64, "Structured", "Mixed", 16, 32, 48, 64)
INSTANTIATE_BENCHMARK(128, "Structured", "Mixed", 32, 64, 96, 128)
INSTANTIATE_BENCHMARK(256, "Structured", "Mixed", 64, 128, 192, 256)