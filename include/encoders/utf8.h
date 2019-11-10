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

#include "encoders/caching_encoder.h"
#include "encoders/utfbase.h"

class UTF8: public UTFBase {
public:
  virtual UTF8* clone() const { return new UTF8(); }

  virtual uint32_t maxByteLength() const { return 4; }

  virtual std::string name() const { return "UTF-8"; }

  virtual uint32_t write(int32_t cp, byte buf[]) const;

  using UTFBase::write;

  virtual uint32_t write(const byte buf[], int32_t& cp) const;

protected:
  virtual void collectRanges(const UnicodeSet& user, std::vector<std::vector<ByteSet>>& v) const;

  virtual void writeRangeBlock(std::vector<ByteSet>& v, uint32_t& l, uint32_t h, uint32_t len, uint32_t blimit) const;
};

class CachingUTF8: public CachingEncoder {
public:
  CachingUTF8(): CachingEncoder(
    UTF8(),
    {
      // \p{Any}, .
      {
        {{0, 0xD800}, {0xE000, 0x110000}},
        {
          { {{0x00, 0x80}} },
          { {{0xC2, 0xE0}}, {{0x80, 0xC0}} },
          {   0xE0,         {{0xA0, 0xC0}}, {{0x80, 0xC0}} },
          {   0xED,         {{0x80, 0xA0}}, {{0x80, 0xC0}} },
          { {{0xE1,0xED}, {0xEE,0xF0}}, {{0x80, 0xC0}}, {{0x80, 0xC0}} },
          {   0xF0,         {{0x90, 0xC0}}, {{0x80, 0xC0}}, {{0x80, 0xC0}} },
          {   0xF4,         {{0x80, 0x90}}, {{0x80, 0xC0}}, {{0x80, 0xC0}} },
          { {{0xF1, 0xF4}}, {{0x80, 0xC0}}, {{0x80, 0xC0}}, {{0x80, 0xC0}} }
        }
      }
    }
  ) {}
};
