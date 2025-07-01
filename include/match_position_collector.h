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

/**
 * Efficient collector for match positions within data chunks.
 * Optimized for sequential scanning where positions are naturally ordered.
 */
class MatchPositionCollector {
public:
    explicit MatchPositionCollector(size_t expectedMatches = 64);
    
    // Add a single match position
    void addPosition(size_t position);
    
    // Add multiple positions efficiently (for SIMD bulk operations)
    void addPositions(const size_t* positions, size_t count);
    
    // Check if any matches were found
    bool hasMatches() const { return !positions_.empty(); }
    
    // Get number of matches found
    size_t getMatchCount() const { return positions_.size(); }
    
    // Get all match positions (naturally ordered from sequential scanning)
    const std::vector<size_t>& getPositions() const;
    
    // Clear for reuse
    void clear();
    
    // Reserve space for expected matches (optimization)
    void reserve(size_t capacity);
    
    // Get positions as raw array (for performance-critical iteration)
    const size_t* data() const { return positions_.data(); }
    
    // Iterator support for range-based loops
    std::vector<size_t>::const_iterator begin() const { return positions_.begin(); }
    std::vector<size_t>::const_iterator end() const { return positions_.end(); }

private:
    std::vector<size_t> positions_;
};