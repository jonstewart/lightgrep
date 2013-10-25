/*
  liblightgrep: not the worst forensics regexp engine
  Copyright (C) 2013, Lightbox Technologies, Inc

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "basic.h"
#include <limits>

#include "instructions.h"

struct Thread {
  static const uint32_t NOLABEL;
  static const uint64_t NONE;

  Thread():
    PC(0),
    Label(NOLABEL),
    #ifdef LBT_TRACE_ENABLED
    Id(0),
    #endif
    Start(0),
    End(NONE) {}

  Thread(const Instruction* pc, uint32_t label, uint64_t start, uint64_t end):
    PC(pc),
    Label(label),
    Start(start),
    End(end) {}

  #ifdef LBT_TRACE_ENABLED
  Thread(const Instruction* pc, uint32_t label,
         uint64_t id, uint64_t start, uint64_t end):
    PC(pc),
    Label(label),
    Id(id),
    Start(start),
    End(end) {}
  #endif

  Thread(const Instruction* pc):
    PC(pc),
    Label(NOLABEL),
    #ifdef LBT_TRACE_ENABLED
    Id(0),
    #endif
    Start(0),
    End(NONE) {}

/*
  Thread(const Thread& t):
    PC(t.PC),
    Label(t.Label),
    #ifdef LBT_TRACE_ENABLED
    Id(t.Id),
    #endif
    Start(t.Start),
    End(t.End) {}

  Thread& operator=(const Thread& t) {
    PC = t.PC;
    Label = t.Label;
    #ifdef LBT_TRACE_ENABLED
    Id = t.Id;
    #endif
    Start = t.Start;
    End = t.End;
  }
*/

/*
  #ifdef LBT_TRACE_ENABLED
  void init(const Instruction* pc, uint32_t label,
            uint64_t id, uint64_t start, uint64_t end) {
    PC = pc;
    Id = id;
    Label = label;
    Start = start;
    End = end;
  }
  #endif

  void init(const Instruction* pc, uint32_t label, uint64_t start, uint64_t end) {
    PC = pc;
    Label = label;
    Start = start;
    End = end;
  }

  void init(const Instruction* base, uint64_t start) {
    PC = base;
    Start = start;
  }
*/

  void jump(const Instruction* base, uint32_t offset) {
    PC = base;
    PC += offset;
  }

  void fork(const Thread& parent, const Instruction* base, uint32_t offset) {
    *this = parent;
    jump(base, offset);
  }

  void advance(uint32_t size) {
    PC += size;
  }

  void advance() {
    PC += PC->wordSize();
  }

  const Instruction* PC;
  uint64_t Start, End;
  #ifdef LBT_TRACE_ENABLED
  uint64_t Id;
  #endif
  uint32_t Label;

  #ifdef LBT_TRACE_ENABLED
  enum ThreadLife {
    BORN = 1,
    PRERUN = 2,
    POSTRUN = 4,
    DIED = 8
  };

  void output_json(std::ostream& out, const Instruction* base, byte state) const;
  #endif

  bool operator==(const Thread& x) const {
    return PC == x.PC && Label == x.Label &&
           Start == x.Start && End == x.End;
  }
};

std::ostream& operator<<(std::ostream& out, const Thread& t);

