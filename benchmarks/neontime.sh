#!/usr/bin/env bash -e
#
# NEON SIMD matcher benchmark using patterns that should benefit from SIMD optimization
# Tests performance with small bigram sets that fit within NEON matcher threshold

for i in $(seq 1 10) ; do
  src/cmd/lightgrep -k pytest/keys/fixed30.txt --verbose --no-output pytest/corpora/norvig6mb.txt 2>&1
done | grep -E '^[0-9]+\.[0-9]+ (searchTime|MB/s)' | python3 pytest/lightgrep_stats.py