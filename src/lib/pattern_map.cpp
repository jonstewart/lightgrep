#include "pattern_map.h"

#include <algorithm>
#include <iterator>
#include <cstring>
#include <memory>
#include <numeric>

void PatternMap::addPattern(const char* pattern, const char* chain, uint64_t idx) {
  std::unique_ptr<char[]> patcopy(new char[std::strlen(pattern)+1]);
  std::strcpy(patcopy.get(), pattern);

  std::unique_ptr<char[]> chcopy(new char[std::strlen(chain)+1]);
  std::strcpy(chcopy.get(), chain);

  usePattern(patcopy.get(), chcopy.get(), idx);
  patcopy.release();
  chcopy.release();
}

void PatternMap::usePattern(const char* pattern, const char* chain, uint64_t idx) {
  Patterns.push_back({pattern, chain, idx});
}

std::vector<char> PatternMap::marshall() const {
  std::vector<char> buf(bufSize());
  char* i = buf.data();
  size_t slen;

  for (const LG_PatternInfo& pi: Patterns) {
    slen = std::strlen(pi.Pattern) + 1;
    std::memcpy(i, pi.Pattern, slen);
    i += slen;

    slen = std::strlen(pi.EncodingChain) + 1; 
    std::memcpy(i, pi.EncodingChain, slen);
    i += slen;

    std::memcpy(i, &pi.UserIndex, sizeof(pi.UserIndex));
    i += sizeof(pi.UserIndex); 
  }

  return buf; 
}

size_t PatternMap::bufSize() const {
  return std::accumulate(
    Patterns.begin(),
    Patterns.end(),
    0,
    [](size_t s, const LG_PatternInfo& pi) {
      return s + std::strlen(pi.Pattern) + 1
               + std::strlen(pi.EncodingChain) + 1
               + sizeof(pi.UserIndex); 
    }
  );
}

template <void(PatternMap::*func)(const char*, const char*, uint64_t)>
std::unique_ptr<PatternMap> unmarshallImpl(const void* buf, size_t len) {
  std::unique_ptr<PatternMap> p(new PatternMap(0));

  const char* i = static_cast<const char*>(buf);
  const char* pat;
  const char* chain;
  const char* idx;
  
  const char* const end = i + len;
  
  while (i < end) {
    pat = i;
    chain = pat + std::strlen(pat) + 1;
    idx = chain + std::strlen(chain) + 1;

    ((*p).*func)(pat, chain, *reinterpret_cast<const uint64_t*>(idx));

    i = idx + sizeof(LG_PatternInfo::UserIndex); 
  }

  return std::move(p);
}

std::unique_ptr<PatternMap> PatternMap::unmarshall(const void* buf, size_t len) {
  return unmarshallImpl<&PatternMap::addPattern>(buf, len);
}

std::unique_ptr<PatternMap> PatternMap::unmarshall_shared(const void* buf, size_t len) {
  std::unique_ptr<PatternMap> p = unmarshallImpl<&PatternMap::usePattern>(buf, len);
  p->Shared = true;
  return std::move(p);
}

bool PatternMap::operator==(const PatternMap& rhs) const {
  return std::equal(Patterns.begin(), Patterns.end(), rhs.Patterns.begin());
}

bool operator==(const LG_PatternInfo& lhs, const LG_PatternInfo& rhs) {
  return lhs.UserIndex == rhs.UserIndex &&
         !std::strcmp(lhs.Pattern, rhs.Pattern) &&
         !std::strcmp(lhs.EncodingChain, rhs.EncodingChain);
}

std::ostream& operator<<(std::ostream& out, const PatternMap& p) {
  out << '[';
  std::copy(p.Patterns.begin(), p.Patterns.end(), std::ostream_iterator<LG_PatternInfo>(out, ", "));
  return out << ']';
}

std::ostream& operator<<(std::ostream& out, const LG_PatternInfo& pi) {
  return out << '['
             << pi.Pattern << ','
             << pi.EncodingChain << ','
             << pi.UserIndex
             << ']';
}
