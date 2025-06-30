#!/usr/bin/env bash -e
#
# Mixed pattern benchmark using combination of fixed strings and simple regexes
# Tests performance with mixed pattern types on medium corpus

for i in $(seq 1 10) ; do
  src/cmd/lightgrep -k pytest/keys/shuf10.txt --verbose --no-output pytest/corpora/norvig1mb.txt 2>&1
done | grep -E '^[0-9]+\.[0-9]+ (searchTime|MB/s)' | python3 pytest/lightgrep_stats.py