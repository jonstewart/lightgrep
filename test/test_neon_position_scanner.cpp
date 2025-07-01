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
#include "neon_position_scanner.h"
#include "match_position_collector.h"

#include <bitset>
#include <vector>
#include <string>
#include <algorithm>

TEST_CASE("NeonPositionScanner basic functionality", "[neon_position_scanner]") {
    
    SECTION("Empty filter") {
        std::bitset<65536> filter; // All zeros
        NeonPositionScanner scanner(filter);
        
        REQUIRE_FALSE(scanner.isApplicable());
        REQUIRE(scanner.getBigramCount() == 0);
    }
    
    SECTION("Single bigram filter") {
        std::bitset<65536> filter;
        uint16_t targetBigram = 0x4142; // "AB"
        filter[targetBigram] = 1;
        
        NeonPositionScanner scanner(filter);
        
        REQUIRE(scanner.isApplicable());
        REQUIRE(scanner.getBigramCount() == 1);
        
        // Test data with the target bigram
        std::string testData = "XYZABDEF";
        MatchPositionCollector collector;
        
        scanner.scanPositions(reinterpret_cast<const uint8_t*>(testData.data()),
                            testData.size(), 0, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 1);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions[0] == 3); // Position of "AB"
    }
    
    SECTION("Multiple bigram filter") {
        std::bitset<65536> filter;
        filter[0x4142] = 1; // "AB"
        filter[0x4344] = 1; // "CD"
        filter[0x4546] = 1; // "EF"
        
        NeonPositionScanner scanner(filter);
        
        REQUIRE(scanner.isApplicable());
        REQUIRE(scanner.getBigramCount() == 3);
        
        // Test data with multiple target bigrams: "ABXCDYEFZ"
        //                                          0123456789
        std::string testData = "ABXCDYEFZ";
        MatchPositionCollector collector;
        
        scanner.scanPositions(reinterpret_cast<const uint8_t*>(testData.data()),
                            testData.size(), 0, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 3);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions[0] == 0); // Position of "AB"
        REQUIRE(positions[1] == 3); // Position of "CD" 
        REQUIRE(positions[2] == 6); // Position of "EF"
    }
    
    SECTION("No matches") {
        std::bitset<65536> filter;
        filter[0x4142] = 1; // "AB"
        
        NeonPositionScanner scanner(filter);
        
        std::string testData = "XYZDEF";
        MatchPositionCollector collector;
        
        scanner.scanPositions(reinterpret_cast<const uint8_t*>(testData.data()),
                            testData.size(), 0, collector);
        
        REQUIRE_FALSE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 0);
    }
    
    SECTION("Filter offset") {
        std::bitset<65536> filter;
        filter[0x4142] = 1; // "AB"
        
        NeonPositionScanner scanner(filter);
        
        // Test data where target is at different position due to offset
        std::string testData = "XYZABDEF";
        MatchPositionCollector collector;
        
        // With offset of 2, we start looking from position 2
        scanner.scanPositions(reinterpret_cast<const uint8_t*>(testData.data()),
                            testData.size(), 2, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 1);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions[0] == 1); // Position relative to offset (3-2=1)
    }
    
    SECTION("Overlapping bigrams") {
        std::bitset<65536> filter;
        filter[0x4141] = 1; // "AA"
        
        NeonPositionScanner scanner(filter);
        
        std::string testData = "BAAA"; // Contains "AA" at positions 1 and 2
        MatchPositionCollector collector;
        
        scanner.scanPositions(reinterpret_cast<const uint8_t*>(testData.data()),
                            testData.size(), 0, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 2);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions[0] == 1);
        REQUIRE(positions[1] == 2);
    }
    
    SECTION("Large bigram set exceeds threshold") {
        std::bitset<65536> filter;
        
        // Add more bigrams than the default threshold
        for (size_t i = 0; i < NeonPositionScanner::DEFAULT_MAX_BIGRAMS + 10; ++i) {
            filter[i] = 1;
        }
        
        NeonPositionScanner scanner(filter);
        
        REQUIRE_FALSE(scanner.isApplicable());
    }
}

TEST_CASE("NeonPositionScanner chunk processing", "[neon_position_scanner]") {
    
    SECTION("Single chunk processing") {
        std::bitset<65536> filter;
        filter[0x4142] = 1; // "AB"
        
        NeonPositionScanner scanner(filter);
        
        std::string chunkData = "XABYZ";
        MatchPositionCollector collector;
        
        scanner.scanChunk(reinterpret_cast<const uint8_t*>(chunkData.data()),
                         chunkData.size(), 0, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 1);
        REQUIRE(collector.getPositions()[0] == 1);
    }
    
    SECTION("Large chunk processing") {
        std::bitset<65536> filter;
        filter[0x4142] = 1; // "AB"
        
        NeonPositionScanner scanner(filter);
        
        // Create a chunk larger than SIMD processing size
        std::string largeChunk(100, 'X');
        largeChunk[10] = 'A';
        largeChunk[11] = 'B';
        largeChunk[50] = 'A';
        largeChunk[51] = 'B';
        
        MatchPositionCollector collector;
        
        scanner.scanChunk(reinterpret_cast<const uint8_t*>(largeChunk.data()),
                         largeChunk.size(), 0, collector);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 2);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions[0] == 10);
        REQUIRE(positions[1] == 50);
    }
}

TEST_CASE("NeonPositionScanner performance benchmarks", "[neon_position_scanner][benchmark]") {
    
    SECTION("Scanner creation benchmark") {
        // Test different bigram set sizes
        std::vector<size_t> bigramCounts = {10, 50, 100, 200};
        
        for (size_t count : bigramCounts) {
            std::bitset<65536> filter;
            for (size_t i = 0; i < count; ++i) {
                filter[i] = 1;
            }
            
            BENCHMARK("Create scanner with " + std::to_string(count) + " bigrams") {
                return NeonPositionScanner(filter);
            };
        }
    }
    
    SECTION("Position scanning benchmark") {
        std::bitset<65536> filter;
        // Create moderate-sized bigram set
        for (size_t i = 0; i < 64; ++i) {
            filter[i] = 1;
        }
        
        NeonPositionScanner scanner(filter);
        
        // Create test data with known patterns
        std::vector<uint8_t> testData(1024);
        for (size_t i = 0; i < testData.size(); ++i) {
            testData[i] = static_cast<uint8_t>(i % 256);
        }
        
        BENCHMARK("Scan 1KB with sparse matches") {
            MatchPositionCollector collector;
            scanner.scanPositions(testData.data(), testData.size(), 0, collector);
            return collector.getMatchCount();
        };
        
        // Create data with no matches
        std::vector<uint8_t> noMatchData(1024, 0xFF);
        
        BENCHMARK("Scan 1KB with no matches") {
            MatchPositionCollector collector;
            scanner.scanPositions(noMatchData.data(), noMatchData.size(), 0, collector);
            return collector.getMatchCount();
        };
        
        // Create data with many matches
        std::vector<uint8_t> manyMatchData(1024);
        for (size_t i = 0; i < manyMatchData.size(); ++i) {
            manyMatchData[i] = static_cast<uint8_t>(i % 64); // Many matches with our filter
        }
        
        BENCHMARK("Scan 1KB with many matches") {
            MatchPositionCollector collector;
            scanner.scanPositions(manyMatchData.data(), manyMatchData.size(), 0, collector);
            return collector.getMatchCount();
        };
    }
}