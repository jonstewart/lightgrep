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

#include "match_position_collector.h"
#include <algorithm>

MatchPositionCollector::MatchPositionCollector(size_t expectedMatches) {
    positions_.reserve(expectedMatches);
}

void MatchPositionCollector::addPosition(size_t position) {
    // Positions arrive naturally ordered during sequential scanning
    positions_.push_back(position);
}

void MatchPositionCollector::addPositions(const size_t* positions, size_t count) {
    if (count == 0) return;
    
    size_t oldSize = positions_.size();
    positions_.reserve(oldSize + count);
    
    for (size_t i = 0; i < count; ++i) {
        positions_.push_back(positions[i]);
    }
}

void MatchPositionCollector::clear() {
    positions_.clear();
}

void MatchPositionCollector::reserve(size_t capacity) {
    positions_.reserve(capacity);
}

const std::vector<size_t>& MatchPositionCollector::getPositions() const {
    return positions_;
}