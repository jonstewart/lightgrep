#!/usr/bin/env bash -e
#
# Fixed string benchmark using simple literal patterns against large corpus
# Tests performance with basic string matching patterns

for i in $(seq 1 10) ; do
  src/cmd/lightgrep -k pytest/keys/fixed30.txt --verbose --no-output pytest/corpora/norvig6mb.txt 2>&1
done | grep -E '^[0-9]+\.[0-9]+ (searchTime|MB/s)' | python3 pytest/lightgrep_stats.py