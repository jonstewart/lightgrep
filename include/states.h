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

#include "byteset.h"
#include "transition.h"
#include "rangeset.h"

struct TransitionComparator;
class TransitionFactory;

enum TransitionType {
  ByteStateType,
  EitherStateType,
  RangeStateType,
  ByteSetStateType
};

class ByteState: public Transition {
public:
  ByteState(byte b): Byte(b) {}
  virtual ~ByteState() {}

  virtual const byte* allowed(const byte* beg, const byte*) const {
    return *beg == Byte ? beg + 1 : beg;
  }

  virtual ByteSet& orBytes(ByteSet& bs) const {
    bs.set(Byte);
    return bs;
  }

  virtual size_t objSize() const { return sizeof(*this); }

  virtual byte type() const { return ByteStateType; }

  virtual ByteState* clone(void* buffer) const;

  virtual size_t numInstructions() const { return 1; };
  virtual bool toInstruction(Instruction* addr) const;
  virtual std::string label() const;

private:
  ByteState(const ByteState& x): Transition(), Byte(x.Byte) {}

  byte Byte;

  friend struct TransitionComparator;
  friend struct TransitionHash;
  friend struct TransitionEqual;
  friend class TransitionFactory;
};

class EitherState: public Transition {
public:
  EitherState(byte one, byte two): Byte1(one), Byte2(two) {}
  virtual ~EitherState() {}

  virtual const byte* allowed(const byte* beg, const byte*) const {
    return *beg == Byte1 || *beg == Byte2 ? beg + 1 : beg;
  }

  virtual ByteSet& orBytes(ByteSet& bs) const {
    bs.set(Byte1);
    bs.set(Byte2);
    return bs;
  }

  virtual byte type() const { return EitherStateType; }

  virtual size_t objSize() const { return sizeof(*this); }

  virtual EitherState* clone(void* buffer) const;

  virtual size_t numInstructions() const { return 1; };
  virtual bool toInstruction(Instruction* addr) const;
  virtual std::string label() const;

private:
  EitherState(const EitherState& x):
    Transition(), Byte1(x.Byte1), Byte2(x.Byte2) {}

  byte Byte1, Byte2;

  friend struct TransitionComparator;
  friend struct TransitionHash;
  friend struct TransitionEqual;
  friend class TransitionFactory;
};

class RangeState: public Transition {
public:
  RangeState(byte first, byte last): First(first), Last(last) {}
  virtual ~RangeState() {}

  virtual const byte* allowed(const byte* beg, const byte*) const {
    return First <= *beg && *beg <= Last ? beg+1: beg;
  }

  virtual ByteSet& orBytes(ByteSet& bs) const {
    return bs.set(First, Last+1, true);
  }

  virtual byte type() const { return RangeStateType; }

  virtual size_t objSize() const { return sizeof(*this); }

  virtual RangeState* clone(void* buffer) const;

  virtual size_t numInstructions() const { return 1; };
  virtual bool toInstruction(Instruction* addr) const;
  virtual std::string label() const;

private:
  RangeState(const RangeState& x): Transition(), First(x.First), Last(x.Last) {}

  byte First, Last;

  friend struct TransitionComparator;
  friend struct TransitionHash;
  friend struct TransitionEqual;
  friend class TransitionFactory;
};

class ByteSetState: public Transition {
public:
  ByteSetState(const ByteSet& allowed): Allowed(allowed) {}

  ByteSetState(const UnicodeSet& allowed) {
    for (uint32_t i = 0; i < 256; ++i) {
      Allowed[i] = allowed[i];
    }
  }

  virtual ~ByteSetState() {}

  virtual const byte* allowed(const byte* beg, const byte*) const {
    return Allowed[*beg] ? beg+1 : beg;
  }

  virtual ByteSet& orBytes(ByteSet& bs) const {
    bs |= Allowed;
    return bs;
  }

  virtual byte type() const { return ByteSetStateType; }

  virtual size_t objSize() const { return sizeof(*this); }

  virtual ByteSetState* clone(void* buffer) const;

  virtual size_t numInstructions() const { return 9; }
  virtual bool toInstruction(Instruction* addr) const;
  virtual std::string label() const;

private:
  ByteSetState(const ByteSetState& x): Transition(), Allowed(x.Allowed) {}

  ByteSet Allowed;

  friend struct TransitionComparator;
  friend struct TransitionHash;
  friend struct TransitionEqual;
  friend class TransitionFactory;
};

// TransitionComparator definition moved to transitionfactory.h
// where it is actually used. Forward declaration kept here for
// friend class declarations.
struct TransitionComparator;
