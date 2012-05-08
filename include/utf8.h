#pragma once

#include "encoder.h"

class UTF8: public Encoder {
public:
  virtual uint32 maxByteLength() const { return 4; }
  virtual uint32 write(int cp, byte buf[]) const;
  using Encoder::write;
};
