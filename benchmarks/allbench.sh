#!/usr/bin/env bash -e
#
# Comprehensive benchmark suite running all performance tests
# Compares different pattern types and corpus sizes

echo "=== Lightgrep Performance Benchmark Suite ==="
echo "Running all benchmarks to compare performance across different pattern types..."
echo ""

echo "1. Fixed String Patterns (30 patterns vs 6MB norvig corpus):"
echo "   Simple literal string matching performance"
./benchmarks/fixedtime.sh
echo ""

echo "2. Mixed Patterns (10 patterns vs 1MB norvig corpus):"
echo "   Combination of fixed strings and simple regexes"
./benchmarks/mixedtime.sh
echo ""

echo "3. Complex Regex Patterns (25 patterns vs 15MB Mark Twain corpus):"
echo "   Advanced regex pattern matching performance"
./benchmarks/regextime.sh
echo ""

echo "4. Original Twain Benchmark (mixed patterns vs 15MB Mark Twain corpus):"
echo "   Baseline comparison with existing benchmark"
./benchmarks/twaintime.sh
echo ""

echo "=== Benchmark Suite Complete ==="