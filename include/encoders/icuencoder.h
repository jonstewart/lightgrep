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

#include "encoders/encoderbase.h"
#include "icuconverter.h"

#include <memory>
#include <string>

class ICUEncoder: public EncoderBase {
public:
  ICUEncoder(const std::string& name);

  ICUEncoder(const ICUEncoder&) = default;

  ICUEncoder& operator=(const ICUEncoder&) = default;

  ICUEncoder(ICUEncoder&&) = default;

  ICUEncoder& operator=(ICUEncoder&&) = default;

  virtual ICUEncoder* clone() const { return new ICUEncoder(*this); }

  virtual uint32_t maxByteLength() const { return Conv.maxByteLength(); }

  virtual std::string name() const { return Conv.name(); }

  virtual uint32_t write(int32_t cp, byte buf[]) const;

  using EncoderBase::write;

  virtual uint32_t write(const byte buf[], int32_t& cp) const;

private:
  ICUConverter Conv;
};
