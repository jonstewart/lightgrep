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

#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <unicode/ucnv.h>

#include "basic.h"
#include "encoders/encoder.h"
#include "encoders/encoderfactory.h"

void write_tests(Encoder& enc, byte* buf_other, byte* buf_enc) {
  UnicodeSet valid(enc.validCodePoints());

  std::cerr << enc.name() << std::endl;

  // get the first and last code points for padding
  const uint32_t first = valid.begin()->first;
  const uint32_t last = (--valid.end())->second - 1;
  uint32_t len_other = enc.write(last, buf_other);

  for (UnicodeSet::range r : valid) {
    for ( ; r.first < r.second; ++r.first) {
      // write pattern count
      const uint32_t pat_count = 1;
      std::cout.write(reinterpret_cast<const char*>(&pat_count), sizeof(pat_count));

      // write pattern as a code point: \x{hhhh}
      std::ostringstream ss;
      ss << "\\x{" << std::hex << r.first << '}';
      const std::string pat(ss.str());
      const uint32_t len_pat = pat.length();

      std::cout.write(reinterpret_cast<const char*>(&len_pat), sizeof(len_pat));
      std::cout << pat;

      // write options
      std::cout.put(0);
      std::cout.put(0);

      // write encoding name
      const uint32_t len_name = enc.name().length();
      std::cout.write(reinterpret_cast<const char*>(&len_name), sizeof(len_name));
      std::cout << enc.name();

      // write text
      const uint32_t len_enc = enc.write(r.first, buf_enc);

      if (len_enc == 0) {
        // ack, this is bogus!
        std::cerr << enc.name() << ' ' << std::hex << r.first << std::endl;
      }

      bool reset_other = r.first == first;

      // can't use encoding of first code point in these cases, as its
      // last byte is the same as the first byte of the target code point
      if (r.first == 0 && enc.name() == "UTF-32LE") {
        // high byte of UTF-32LE is always empty, so we have to fill it
        *reinterpret_cast<uint32_t*>(buf_other) = 0xFFFFFFFF;
        reset_other = true;
      }
      else if (r.first == 0x6883 && enc.name() == "ibm-5478_P100-1995") {
        len_other = enc.write(last, buf_other);
        reset_other = true;
      }

      // write the text as xAx
      const uint32_t len_tot = 2*len_other + len_enc;
      std::cout.write(reinterpret_cast<const char*>(&len_tot), sizeof(len_tot));
      std::cout.write(reinterpret_cast<char*>(buf_other), len_other);
      std::cout.write(reinterpret_cast<char*>(buf_enc), len_enc);
      std::cout.write(reinterpret_cast<char*>(buf_other), len_other);

      // write match count
      const uint32_t match_count = 1;
      std::cout.write(reinterpret_cast<const char*>(&match_count), sizeof(match_count));

      // write matches
      const uint64_t match_beg = len_other, match_end = len_other + len_enc, pat_num = 0;
      std::cout.write(reinterpret_cast<const char*>(&match_beg), sizeof(match_beg));
      std::cout.write(reinterpret_cast<const char*>(&match_end), sizeof(match_end));
      std::cout.write(reinterpret_cast<const char*>(&pat_num), sizeof(pat_num));

      if (reset_other) {
        // switch padding to first code point
        len_other = enc.write(first, buf_other);
      }
    }
  }
}

int main(int argc, char** argv) {
  std::vector<std::string> encodings;

  if (argc > 1) {
    // produce tests for the requested encodings
    encodings.assign(argv + 1, argv + argc);
  }
  else {
    // produce tests for all encodings

    //
    // Encodings provided by Lightgrep
    //
    encodings.insert(encodings.end(), {
      "ASCII",
      "UTF-8",
      "UTF-16LE",
      "UTF-16BE",
      "UTF-32LE",
      "UTF-32BE"
    });

    //
    // Encodings provided by ICU
    //

    // Encodings to skip with ICU
    const std::set<std::string> skip{
      // we provide these, use ours
      "ASCII",
      "UTF-8",
      "UTF-16LE",
      "UTF-16BE",
      "UTF-32LE",
      "UTF-32BE",

      // skip these due to BOMs
      "UTF-16",
      "UTF-16,version=1",
      "UTF-16,version=2",
      "UTF-16LE,version=1",
      "UTF-16BE,version=1",
      "UTF-32",

      // skip these because they're confusing
      "UTF16_OppositeEndian",
      "UTF16_PlatformEndian",
      "UTF32_OppositeEndian",
      "UTF32_PlatformEndian",

      // stateful
      "BOCU-1",               // IBM MIME-friendly Unicode encoding
      "HZ",
      "IMAP-mailbox-name",    // modified UTF-7
      "ISCII,version=0",      // Indian Script Code for Information Interchange
      "ISCII,version=1",
      "ISCII,version=2",
      "ISCII,version=3",
      "ISCII,version=4",
      "ISCII,version=5",
      "ISCII,version=6",
      "ISCII,version=7",
      "ISCII,version=8",
      "ISO_2022,locale=ja,version=0",
      "ISO_2022,locale=ja,version=1",
      "ISO_2022,locale=ja,version=2",
      "ISO_2022,locale=ja,version=3",
      "ISO_2022,locale=ja,version=4",
      "ISO_2022,locale=ko,version=0",
      "ISO_2022,locale=ko,version=1",
      "ISO_2022,locale=zh,version=0",
      "ISO_2022,locale=zh,version=1",
      "ISO_2022,locale=zh,version=2",
      "LMBCS-1",  // Louts Multi-Byte Character Set
                  // http://web.archive.org/web/20050516054001/http://www.batutis.com/i18n/papers/lmbcs/LMBCS.html
      "SCSU",                 // Symbian, SQL Server 2008, Reuters
      "UTF-7",                // crazy
      "ibm-930_P120-1999",
      "ibm-933_P110-1995",
      "ibm-935_P110-1999",
      "ibm-937_P110-1999",
      "ibm-939_P120-1999",
      "ibm-1364_P110-2007",
      "ibm-1371_P100-1999",
      "ibm-1388_P103-2001",
      "ibm-1390_P110-2003",
      "ibm-1399_P110-2003",
      "ibm-16684_P110-2003",
      "x11-compound-text"     // http://www.x.org/docs/CTEXT/ctext.pdf
    };

    const int32_t clen = ucnv_countAvailable();
    for (int32_t i = 0; i < clen; ++i) {
      const char* name = ucnv_getAvailableName(i);

      // skip encodings we want to omit
      if (skip.find(name) == skip.end()) {
        encodings.push_back(name);
      }
    }
  }

  // generate test data for each requested encoding
  EncoderFactory efac;
  for (const std::string& ename : encodings) {
    std::shared_ptr<Encoder> enc(efac.get(ename));
    std::unique_ptr<byte[]> buf_other(new byte[enc->maxByteLength()]);
    std::unique_ptr<byte[]> buf_enc(new byte[enc->maxByteLength()]);
    write_tests(*enc.get(), buf_other.get(), buf_enc.get());
  }

  return 0;
}
