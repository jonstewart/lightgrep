#!/usr/bin/env bash -e
#
# Regex benchmark using complex regular expression patterns
# Tests performance with primarily regex patterns on large corpus

for i in $(seq 1 10) ; do
  src/cmd/lightgrep -k pytest/keys/shuf25.txt --verbose --no-output pytest/corpora/marktwainworks.txt 2>&1
done | grep -E '^[0-9]+\.[0-9]+ (searchTime|MB/s)' | python3 pytest/lightgrep_stats.py