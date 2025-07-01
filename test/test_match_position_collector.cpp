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
#include "match_position_collector.h"

#include <vector>
#include <algorithm>
#include <random>
#include <numeric>

TEST_CASE("MatchPositionCollector basic functionality", "[match_position_collector]") {
    MatchPositionCollector collector;
    
    SECTION("Empty collector") {
        REQUIRE_FALSE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 0);
        REQUIRE(collector.getPositions().empty());
    }
    
    SECTION("Single position") {
        collector.addPosition(42);
        
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 1);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions.size() == 1);
        REQUIRE(positions[0] == 42);
    }
    
    SECTION("Multiple positions in order") {
        collector.addPosition(10);
        collector.addPosition(20);
        collector.addPosition(30);
        
        REQUIRE(collector.getMatchCount() == 3);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions.size() == 3);
        REQUIRE(positions[0] == 10);
        REQUIRE(positions[1] == 20);
        REQUIRE(positions[2] == 30);
    }
    
    SECTION("Multiple positions in order") {
        collector.addPosition(10);
        collector.addPosition(20);
        collector.addPosition(30);
        
        REQUIRE(collector.getMatchCount() == 3);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions.size() == 3);
        REQUIRE(positions[0] == 10);
        REQUIRE(positions[1] == 20);
        REQUIRE(positions[2] == 30);
    }
    
    SECTION("Bulk add positions") {
        size_t bulk_positions[] = {10, 20, 30, 40, 50};
        collector.addPositions(bulk_positions, 5);
        
        REQUIRE(collector.getMatchCount() == 5);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions.size() == 5);
        REQUIRE(positions[0] == 10);
        REQUIRE(positions[4] == 50);
        
        // Check all values are present in order
        REQUIRE(std::find(positions.begin(), positions.end(), 10) != positions.end());
        REQUIRE(std::find(positions.begin(), positions.end(), 50) != positions.end());
    }
    
    SECTION("Positions preserved as added") {
        collector.addPosition(10);
        collector.addPosition(20);
        collector.addPosition(30);
        
        const auto& positions = collector.getPositions();
        REQUIRE(positions.size() == 3);
        REQUIRE(positions[0] == 10);
        REQUIRE(positions[1] == 20);
        REQUIRE(positions[2] == 30);
    }
    
    SECTION("Clear functionality") {
        collector.addPosition(10);
        collector.addPosition(20);
        REQUIRE(collector.hasMatches());
        
        collector.clear();
        REQUIRE_FALSE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 0);
        REQUIRE(collector.getPositions().empty());
        
        // Should be reusable after clear
        collector.addPosition(100);
        REQUIRE(collector.hasMatches());
        REQUIRE(collector.getMatchCount() == 1);
    }
    
    SECTION("Iterator support") {
        collector.addPosition(10);
        collector.addPosition(20);
        collector.addPosition(30);
        
        std::vector<size_t> iterated_positions;
        for (size_t pos : collector) {
            iterated_positions.push_back(pos);
        }
        
        REQUIRE(iterated_positions.size() == 3);
        REQUIRE(iterated_positions[0] == 10);
        REQUIRE(iterated_positions[1] == 20);
        REQUIRE(iterated_positions[2] == 30);
    }
}

TEST_CASE("MatchPositionCollector performance characteristics", "[match_position_collector][benchmark]") {
    
    SECTION("Single position addition benchmark") {
        MatchPositionCollector collector(1000);
        
        BENCHMARK("Add 1000 sequential positions") {
            collector.clear();
            for (size_t i = 0; i < 1000; ++i) {
                collector.addPosition(i);
            }
            return collector.getMatchCount();
        };
        
        BENCHMARK("Add 1000 random positions") {
            collector.clear();
            std::random_device rd;
            std::mt19937 gen(42); // Fixed seed for reproducibility
            std::uniform_int_distribution<size_t> dis(0, 10000);
            
            for (size_t i = 0; i < 1000; ++i) {
                collector.addPosition(dis(gen));
            }
            return collector.getMatchCount();
        };
    }
    
    SECTION("Bulk position addition benchmark") {
        MatchPositionCollector collector(1000);
        
        // Create test data
        std::vector<size_t> sequential_positions(1000);
        std::iota(sequential_positions.begin(), sequential_positions.end(), 0);
        
        std::vector<size_t> random_positions(1000);
        std::random_device rd;
        std::mt19937 gen(42);
        std::uniform_int_distribution<size_t> dis(0, 10000);
        std::generate(random_positions.begin(), random_positions.end(), [&]() { return dis(gen); });
        
        BENCHMARK("Bulk add 1000 sequential positions") {
            collector.clear();
            collector.addPositions(sequential_positions.data(), sequential_positions.size());
            return collector.getMatchCount();
        };
        
        BENCHMARK("Bulk add 1000 random positions") {
            collector.clear();
            collector.addPositions(random_positions.data(), random_positions.size());
            return collector.getMatchCount();
        };
    }
    
    SECTION("Position retrieval benchmark") {
        MatchPositionCollector collector;
        
        // Add 1000 random positions
        std::random_device rd;
        std::mt19937 gen(42);
        std::uniform_int_distribution<size_t> dis(0, 10000);
        
        for (size_t i = 0; i < 1000; ++i) {
            collector.addPosition(dis(gen));
        }
        
        BENCHMARK("Get sorted positions") {
            return collector.getPositions().size();
        };
        
        BENCHMARK("Iterate through positions") {
            size_t sum = 0;
            for (size_t pos : collector) {
                sum += pos;
            }
            return sum;
        };
    }
}