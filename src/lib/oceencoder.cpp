/*
  liblightgrep: not the worst forensics regexp engine
  Copyright (C) 2012 Lightbox Technologies, Inc

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

#include <algorithm>

#include "encoders/oceencoder.h"

void OCEEncoder::byteTransform(byte buf[], uint32_t blen) const {
  std::transform(buf, buf+blen, buf, [](byte b){ return OCE[b]; });
}

const byte OCEEncoder::OCE[] = {
  0x41, 0x36, 0x13, 0x62, 0xA8, 0x21, 0x6E, 0xBB,
  0xF4, 0x16, 0xCC, 0x04, 0x7F, 0x64, 0xE8, 0x5D,
  0x1E, 0xF2, 0xCB, 0x2A, 0x74, 0xC5, 0x5E, 0x35,
  0xD2, 0x95, 0x47, 0x9E, 0x96, 0x2D, 0x9A, 0x88,
  0x4C, 0x7D, 0x84, 0x3F, 0xDB, 0xAC, 0x31, 0xB6,
  0x48, 0x5F, 0xF6, 0xC4, 0xD8, 0x39, 0x8B, 0xE7,
  0x23, 0x3B, 0x38, 0x8E, 0xC8, 0xC1, 0xDF, 0x25,
  0xB1, 0x20, 0xA5, 0x46, 0x60, 0x4E, 0x9C, 0xFB,
  0xAA, 0xD3, 0x56, 0x51, 0x45, 0x7C, 0x55, 0x00,
  0x07, 0xC9, 0x2B, 0x9D, 0x85, 0x9B, 0x09, 0xA0,
  0x8F, 0xAD, 0xB3, 0x0F, 0x63, 0xAB, 0x89, 0x4B,
  0xD7, 0xA7, 0x15, 0x5A, 0x71, 0x66, 0x42, 0xBF,
  0x26, 0x4A, 0x6B, 0x98, 0xFA, 0xEA, 0x77, 0x53,
  0xB2, 0x70, 0x05, 0x2C, 0xFD, 0x59, 0x3A, 0x86,
  0x7E, 0xCE, 0x06, 0xEB, 0x82, 0x78, 0x57, 0xC7,
  0x8D, 0x43, 0xAF, 0xB4, 0x1C, 0xD4, 0x5B, 0xCD,
  0xE2, 0xE9, 0x27, 0x4F, 0xC3, 0x08, 0x72, 0x80,
  0xCF, 0xB0, 0xEF, 0xF5, 0x28, 0x6D, 0xBE, 0x30,
  0x4D, 0x34, 0x92, 0xD5, 0x0E, 0x3C, 0x22, 0x32,
  0xE5, 0xE4, 0xF9, 0x9F, 0xC2, 0xD1, 0x0A, 0x81,
  0x12, 0xE1, 0xEE, 0x91, 0x83, 0x76, 0xE3, 0x97,
  0xE6, 0x61, 0x8A, 0x17, 0x79, 0xA4, 0xB7, 0xDC,
  0x90, 0x7A, 0x5C, 0x8C, 0x02, 0xA6, 0xCA, 0x69,
  0xDE, 0x50, 0x1A, 0x11, 0x93, 0xB9, 0x52, 0x87,
  0x58, 0xFC, 0xED, 0x1D, 0x37, 0x49, 0x1B, 0x6A,
  0xE0, 0x29, 0x33, 0x99, 0xBD, 0x6C, 0xD9, 0x94,
  0xF3, 0x40, 0x54, 0x6F, 0xF0, 0xC6, 0x73, 0xB8,
  0xD6, 0x3E, 0x65, 0x18, 0x44, 0x1F, 0xDD, 0x67,
  0x10, 0xF1, 0x0C, 0x19, 0xEC, 0xAE, 0x03, 0xA1,
  0x14, 0x7B, 0xA9, 0x0B, 0xFF, 0xF8, 0xA3, 0xC0,
  0xA2, 0x01, 0xF7, 0x2E, 0xBC, 0x24, 0x68, 0x75,
  0x0D, 0xFE, 0xBA, 0x2F, 0xB5, 0xD0, 0xDA, 0x3D
};
