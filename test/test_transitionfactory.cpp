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

#include "states.h"
#include "transition.h"
#include "transitionfactory.h"

template <class StateType>
void smallestTester(const ByteSet& ebs) {
  TransitionFactory tfac;
  StateType* state = dynamic_cast<StateType*>(tfac.getSmallest(ebs));
  REQUIRE(state);
  ByteSet abs;
  state->getBytes(abs);
  REQUIRE(ebs == abs);
}

TEST_CASE("getSmallestNoneTest") {
  const ByteSet ebs;
  smallestTester<ByteSetState>(ebs);
}

TEST_CASE("getSmallestOneTest") {
  const ByteSet ebs('z');
  smallestTester<ByteState>(ebs);
}

TEST_CASE("getSmallestTwoTest") {
  ByteSet ebs;
  ebs.set('a');
  ebs.set('z');
  smallestTester<EitherState>(ebs);
}

TEST_CASE("getSmallestRangeTest") {
  ByteSet ebs;
  ebs.set('a', 'z' + 1, true);
  smallestTester<RangeState>(ebs);
}

TEST_CASE("getSmallestManyTest") {
  ByteSet ebs;
  ebs.set('A');
  ebs.set('a');
  ebs.set('b');
  smallestTester<ByteSetState>(ebs);
}

TEST_CASE("transitionFactoryUniquePtrMemoryManagement") {
  // Test that TransitionFactory properly manages memory with unique_ptr
  // and provides consistent pointer identity for equivalent transitions
  TransitionFactory tfac;
  
  // Get the same transition multiple times
  Transition* t1 = tfac.getByte('a');
  Transition* t2 = tfac.getByte('a');
  
  // Should return the same pointer for equivalent transitions
  REQUIRE(t1 == t2);
  
  // Get different transitions
  Transition* t3 = tfac.getByte('b');
  REQUIRE(t1 != t3);
  
  // Verify transitions work correctly
  ByteSet bs1, bs2, bs3;
  t1->getBytes(bs1);
  t2->getBytes(bs2);
  t3->getBytes(bs3);
  
  REQUIRE(bs1 == bs2);
  REQUIRE(bs1 != bs3);
  REQUIRE(bs1.test('a'));
  REQUIRE(bs3.test('b'));
}

TEST_CASE("transitionFactoryUnorderedSetBehavior") {
  // Test that TransitionFactory works correctly with unordered_set
  // by verifying hash and equality behavior for all transition types
  TransitionFactory tfac;
  
  // Test ByteState transitions
  Transition* byte_a1 = tfac.getByte('a');
  Transition* byte_a2 = tfac.getByte('a');  // Should get same instance
  Transition* byte_b = tfac.getByte('b');   // Should get different instance
  
  REQUIRE(byte_a1 == byte_a2);  // Same content should return same pointer
  REQUIRE(byte_a1 != byte_b);   // Different content should return different pointer
  
  // Test EitherState transitions
  Transition* either_ab1 = tfac.getEither('a', 'b');
  Transition* either_ab2 = tfac.getEither('a', 'b');  // Should get same instance
  Transition* either_cd = tfac.getEither('c', 'd');   // Should get different instance
  
  REQUIRE(either_ab1 == either_ab2);  // Same content should return same pointer
  REQUIRE(either_ab1 != either_cd);   // Different content should return different pointer
  
  // Test RangeState transitions
  Transition* range_az1 = tfac.getRange('a', 'z');
  Transition* range_az2 = tfac.getRange('a', 'z');    // Should get same instance
  Transition* range_09 = tfac.getRange('0', '9');     // Should get different instance
  
  REQUIRE(range_az1 == range_az2);  // Same content should return same pointer
  REQUIRE(range_az1 != range_09);   // Different content should return different pointer
  
  // Test ByteSetState transitions
  ByteSet bs1, bs2, bs3;
  bs1.set('a'); bs1.set('b'); bs1.set('c');
  bs2.set('a'); bs2.set('b'); bs2.set('c');  // Same as bs1
  bs3.set('x'); bs3.set('y'); bs3.set('z');  // Different from bs1
  
  Transition* bset1 = tfac.getByteSet(bs1);
  Transition* bset2 = tfac.getByteSet(bs2);  // Should get same instance
  Transition* bset3 = tfac.getByteSet(bs3);  // Should get different instance
  
  REQUIRE(bset1 == bset2);  // Same content should return same pointer
  REQUIRE(bset1 != bset3);  // Different content should return different pointer
  
  // Test that different types are always different (important for unordered_set)
  REQUIRE(byte_a1 != either_ab1);  // Different types should never be equal
  REQUIRE(byte_a1 != range_az1);   // Different types should never be equal
  REQUIRE(byte_a1 != bset1);       // Different types should never be equal
}
