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

#include <algorithm>
#include <functional>
#include <memory>
#include <set>
#include <unordered_set>

#include "byteset.h"
#include "transition.h"
#include "states.h"

// Forward declaration from states.h
struct TransitionComparator {
  //
  // This defines a total ordering over Transitions, such that
  //
  //   ByteState < EitherState < RangeState < ByteSetState
  //
  // and for two Transitions of the same type, the one with the
  // lexicographically least data is the lesser.
  //
  bool operator()(const Transition* a, const Transition* b) const {
    switch (a->type()) {
    case ByteStateType:
      switch (b->type()) {
      case ByteStateType:
        return static_cast<const ByteState*>(a)->Byte <
               static_cast<const ByteState*>(b)->Byte;
      case EitherStateType:
      case RangeStateType:
      case ByteSetStateType:
        return true;
      default:
        THROW_RUNTIME_ERROR_WITH_OUTPUT("Impossible! " << b->type());
      }
    case EitherStateType:
      switch (b->type()) {
      case ByteStateType:
        return false;
      case EitherStateType:
        {
          const EitherState* ae = static_cast<const EitherState*>(a);
          const EitherState* be = static_cast<const EitherState*>(b);

          if (ae->Byte1 < be->Byte1) {
            return true;
          }
          else if (ae->Byte1 > be->Byte1) {
            return false;
          }
          else {
            return ae->Byte2 < be->Byte2;
          }
        }
      case RangeStateType:
      case ByteSetStateType:
        return true;
      default:
        THROW_RUNTIME_ERROR_WITH_OUTPUT("Impossible! " << b->type());
      }
    case RangeStateType:
      switch (b->type()) {
      case ByteStateType:
      case EitherStateType:
        return false;
      case RangeStateType:
        {
          const RangeState* ar = static_cast<const RangeState*>(a);
          const RangeState* br = static_cast<const RangeState*>(b);

          if (ar->First < br->First) {
            return true;
          }
          else if (ar->First > br->First) {
            return false;
          }
          else {
            return ar->Last < br->Last;
          }
        }
      case ByteSetStateType:
        return true;
      default:
        THROW_RUNTIME_ERROR_WITH_OUTPUT("Impossible! " << b->type());
      }
    case ByteSetStateType:
      switch (b->type()) {
      case ByteStateType:
      case EitherStateType:
      case RangeStateType:
        return false;
      case ByteSetStateType:
        return static_cast<const ByteSetState*>(a)->Allowed <
               static_cast<const ByteSetState*>(b)->Allowed;
      default:
        THROW_RUNTIME_ERROR_WITH_OUTPUT("Impossible! " << b->type());
      }
    default:
      THROW_RUNTIME_ERROR_WITH_OUTPUT("Impossible! " << a->type());
    }
  }
};

// Hash function for Transition objects
struct TransitionHash {
private:
  // Efficient hash combining using the standard approach
  static std::size_t hash_combine(std::size_t seed, std::size_t value) {
    return seed ^ (value + 0x9e3779b9 + (seed << 6) + (seed >> 2));
  }

public:
  std::size_t operator()(const Transition* t) const {
    std::size_t result = std::hash<byte>{}(t->type());
    
    switch (t->type()) {
    case ByteStateType:
      {
        const ByteState* bs = static_cast<const ByteState*>(t);
        return hash_combine(result, std::hash<byte>{}(bs->Byte));
      }
    case EitherStateType:
      {
        const EitherState* es = static_cast<const EitherState*>(t);
        result = hash_combine(result, std::hash<byte>{}(es->Byte1));
        return hash_combine(result, std::hash<byte>{}(es->Byte2));
      }
    case RangeStateType:
      {
        const RangeState* rs = static_cast<const RangeState*>(t);
        result = hash_combine(result, std::hash<byte>{}(rs->First));
        return hash_combine(result, std::hash<byte>{}(rs->Last));
      }
    case ByteSetStateType:
      {
        const ByteSetState* bss = static_cast<const ByteSetState*>(t);
        // Use the optimized for_each_set_bit method for better performance
        bss->Allowed.for_each_set_bit([&result](uint64_t bit) {
          result = hash_combine(result, std::hash<uint64_t>{}(bit));
        });
        return result;
      }
    default:
      return result;  // Fallback for unknown types
    }
  }
};

// Equality function for Transition objects
struct TransitionEqual {
  bool operator()(const Transition* a, const Transition* b) const {
    if (a->type() != b->type()) {
      return false;
    }
    
    switch (a->type()) {
    case ByteStateType:
      return static_cast<const ByteState*>(a)->Byte == 
             static_cast<const ByteState*>(b)->Byte;
    case EitherStateType:
      {
        const EitherState* ae = static_cast<const EitherState*>(a);
        const EitherState* be = static_cast<const EitherState*>(b);
        return ae->Byte1 == be->Byte1 && ae->Byte2 == be->Byte2;
      }
    case RangeStateType:
      {
        const RangeState* ar = static_cast<const RangeState*>(a);
        const RangeState* br = static_cast<const RangeState*>(b);
        return ar->First == br->First && ar->Last == br->Last;
      }
    case ByteSetStateType:
      return static_cast<const ByteSetState*>(a)->Allowed == 
             static_cast<const ByteSetState*>(b)->Allowed;
    default:
      return false;  // Unknown types are never equal
    }
  }
};

// Hash function for unique_ptr<Transition> - delegates to raw pointer version
struct TransitionUniquePtrHash : TransitionHash {
  using TransitionHash::operator();
  std::size_t operator()(const std::unique_ptr<Transition>& t) const {
    return TransitionHash::operator()(t.get());
  }
};

// Equality function for unique_ptr<Transition> - delegates to raw pointer version
struct TransitionUniquePtrEqual : TransitionEqual {
  using TransitionEqual::operator();
  bool operator()(const std::unique_ptr<Transition>& a, const std::unique_ptr<Transition>& b) const {
    return TransitionEqual::operator()(a.get(), b.get());
  }
};

// Comparator for unique_ptr<Transition> that supports heterogeneous lookup.
// This allows std::set::find() to work with raw Transition* pointers
// while maintaining the original ordering semantics.
struct TransitionUniquePtrComparator {
  using is_transparent = void;  // Enable heterogeneous lookup in C++14+
  
  // Compare two unique_ptr<Transition>
  bool operator()(const std::unique_ptr<Transition>& a, const std::unique_ptr<Transition>& b) const {
    return TransitionComparator{}(a.get(), b.get());
  }
  
  // Compare unique_ptr<Transition> with raw Transition*
  bool operator()(const std::unique_ptr<Transition>& a, const Transition* b) const {
    return TransitionComparator{}(a.get(), b);
  }
  
  // Compare raw Transition* with unique_ptr<Transition>
  bool operator()(const Transition* a, const std::unique_ptr<Transition>& b) const {
    return TransitionComparator{}(a, b.get());
  }
};

class TransitionFactory {
public:
  TransitionFactory():
    Byte(0), Either(0, 0), Range(0, 0), BSet(ByteSet()) {}

  ~TransitionFactory() = default;

  Transition* getByte(byte b) {
    Byte.Byte = b;
    return get(&Byte);
  }

  Transition* getEither(byte b1, byte b2) {
    Either.Byte1 = b1;
    Either.Byte2 = b2;
    return get(&Either);
  }

  Transition* getRange(byte first, byte last) {
    Range.First = first;
    Range.Last = last;
    return get(&Range);
  }

  Transition* getByteSet(const ByteSet& bset) {
    BSet.Allowed = bset;
    return get(&BSet);
  }

  Transition* getByteSet(const UnicodeSet& bset) {
    // NB: This should be used *only* when we intend to intersect
    // the input set with [0x00,0xFF].
    for (uint32_t i = 0; i < 256; ++i) {
      BSet.Allowed.set(i, bset.test(i));
    }
    return get(&BSet);
  }

  Transition* getSmallest(const ByteSet& bset) {
    enum {
      NONE,
      ONE,
      RANGE,
      TWO
    } type = NONE;

    byte low = 0, high = 0;

    // This is a little state machine for classifying our byte set.
    for (size_t i = 0; i < 256; ++i) {
      if (bset.test(i)) {
        switch (type) {
        case NONE:
          low = high = i;
          type = ONE;
          break;
        case ONE:
          if (++high != i) {
            high = i;
            type = TWO;
          }
          else {
            type = RANGE;
          }
          break;
        case RANGE:
          if (++high == i) {
            break;
          }
        case TWO:
          // cc is a union of disjoint ranges
          return getByteSet(bset);
        }
      }
    }

    switch (type) {
    case NONE:
      return getByteSet(bset);
    case ONE:
      return getByte(low);
    case RANGE:
// TODO: Check whether there is any performance difference between EITHER
// and RANGE for two-element ranges.
      return getRange(low, high);
    case TWO:
      return getEither(low, high);
    }

    // This is impossible, it's here just to shut the compiler up.
    return getByteSet(bset);
  }

  Transition* get(Transition* t) {
    // Create a temporary unique_ptr for lookup
    std::unique_ptr<Transition> temp(t->clone());
    auto i = Exemplars.find(temp);
    if (i == Exemplars.end()) {
      // Store the cloned transition and return raw pointer
      auto result = Exemplars.insert(std::move(temp));
      return result.first->get();
    } else {
      // Return raw pointer to existing transition
      return i->get();
    }
  }

private:
  std::unordered_set<std::unique_ptr<Transition>, TransitionUniquePtrHash, TransitionUniquePtrEqual> Exemplars;

  // Local states so we don't have to create one on each lookup
  ByteState Byte;
  EitherState Either;
  RangeState Range;
  ByteSetState BSet;
};
