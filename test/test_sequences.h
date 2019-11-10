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

#include <scope/test.h>

#include <vector>

#include "basic.h"
#include "listops.h"

SCOPE_TEST(removeRightDuplicatesTest) {
  std::vector<uint32_t> v{7,9,7,9};
  removeRightDuplicates(v);
  std::vector<uint32_t> exp{7,9};
  SCOPE_ASSERT_EQUAL(exp, v);
}
