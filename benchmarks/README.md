# Lightgrep Performance Benchmarks

This directory contains performance benchmark scripts for testing lightgrep under different workloads.

## Available Benchmarks

### `twaintime.sh` (Original)
- **Patterns**: Mixed regex patterns from `pytest/keys/twain.txt` 
- **Corpus**: Mark Twain works (15MB)
- **Purpose**: Baseline benchmark with complex regex patterns
- **Typical Performance**: ~24 MB/s

### `fixedtime.sh` (Fixed Strings)
- **Patterns**: 30 literal string patterns from `pytest/keys/fixed30.txt`
- **Corpus**: Norvig 6MB corpus 
- **Purpose**: Tests pure string matching performance
- **Typical Performance**: ~216 MB/s

### `mixedtime.sh` (Mixed Patterns)
- **Patterns**: 10 mixed string/regex patterns from `pytest/keys/shuf10.txt`
- **Corpus**: Norvig 1MB corpus
- **Purpose**: Tests moderate complexity pattern matching
- **Typical Performance**: ~28 MB/s

### `regextime.sh` (Complex Regex)
- **Patterns**: 25 complex regex patterns from `pytest/keys/shuf25.txt`
- **Corpus**: Mark Twain works (15MB)
- **Purpose**: Tests heavy regex processing performance
- **Typical Performance**: ~28 MB/s

### `allbench.sh` (Comprehensive Suite)
- Runs all benchmarks in sequence with descriptive output
- Useful for performance regression testing
- Provides comparison across different workload types

## Usage

```bash
# Run individual benchmarks
./benchmarks/fixedtime.sh
./benchmarks/mixedtime.sh  
./benchmarks/regextime.sh
./benchmarks/twaintime.sh

# Run all benchmarks
./benchmarks/allbench.sh
```

## Output Format

All benchmarks output statistics in this format:
```
col        min        max        avg        harm       med        var
searchTime 0.628713   0.634072   0.628725   0.628713   0.627128   0.000008
MB/s avg   24.085700  24.387900  24.291030  24.290546  24.339700  0.011716
```

- **searchTime**: Search execution time in seconds
- **MB/s avg**: Average throughput in megabytes per second
- **min/max**: Minimum and maximum values across 10 runs
- **avg**: Arithmetic mean
- **harm**: Harmonic mean (often more representative for performance)
- **med**: Median value
- **var**: Population variance

## Performance Insights

The benchmarks reveal lightgrep's performance characteristics:

1. **Fixed strings** (~216 MB/s): Excellent performance on literal matching
2. **Mixed patterns** (~28 MB/s): Good performance on typical workloads  
3. **Complex regex** (~28 MB/s): Consistent performance even with heavy regex processing
4. **Original benchmark** (~24 MB/s): Baseline for regression testing

This performance profile makes lightgrep well-suited for forensics applications requiring both high throughput and complex pattern matching capabilities.