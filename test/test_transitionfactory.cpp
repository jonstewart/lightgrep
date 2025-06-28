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

TEST_CASE("transitionFactoryUniquePtrMemoryManagement", "[!shouldfail]") {
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
