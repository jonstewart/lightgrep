# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System and Common Commands

Lightgrep uses GNU Autotools as the primary build system.

### Building the Project

**Primary build process (Autotools):**
```bash
# Initial setup (first time only)
autoreconf -fi
./configure --prefix=/Users/jon/build
make -j8

```

```

### Testing

**Run unit tests:**
```bash
make -j8 check                    # Build and run all tests
```

**Python tests (if enabled):**
```bash
pylightgrep/test.sh
```

### Build Options

**Configure flags:**
- `--enable-debug`: Build with debug symbols and no optimization
- `--enable-java`: Build Java bindings
- `--enable-python`: Build Python bindings
- `--without-icu`: Build without ICU (Unicode support)
- `--with-asan=DIR`: Build with AddressSanitizer

**Dependencies:**
- C++17 compiler (GCC or Clang)
- GNU Autotools, Bison, pkg-config
- Boost (headers + program_options)
- ICU libraries (recommended)
- Catch2 (for tests)

## Architecture Overview

Lightgrep is a forensics-focused regular expression engine designed for multi-pattern binary stream searching.

### Core Components

**Multi-Phase Compilation Pipeline:**
1. **Parsing**: Bison parser (`src/lib/re_grammar.ypp`) converts regex patterns to parse trees
2. **NFA Construction**: `NFABuilder` creates non-deterministic finite automata from parse trees
3. **Optimization**: `NFAOptimizer` applies performance optimizations
4. **Code Generation**: `Compiler` generates bytecode programs from optimized NFAs
5. **Execution**: Virtual machine executes bytecode against input streams

**Key Source Directories:**
- `src/lib/`: Core engine implementation (C++ library)
- `src/cmd/`: Command-line application
- `include/lightgrep/`: Public C API headers
- `include/`: Internal headers organized by component
- `src/java/`: Java bindings (JNI)
- `pylightgrep/`: Python bindings (ctypes)

### Design Principles

- **Streaming**: Single-pass processing, never backtracks or re-reads input
- **Multi-pattern**: Efficiently searches for thousands of patterns simultaneously
- **Encoding-aware**: Searches across multiple text encodings (UTF-8, UTF-16, etc.)
- **Binary-focused**: Designed for forensics applications on dirty/corrupted data
- **Automata-based**: Uses finite state machines rather than backtracking algorithms

### API Structure

**C Library Interface** (`include/lightgrep/api.h`):
- Pattern management: `lg_create_pattern()`, `lg_parse_pattern()`
- FSM construction: `lg_create_fsm()`, `lg_add_pattern()`
- Program compilation: `lg_create_program()`
- Search execution: `lg_create_context()`, `lg_search()`

**Command-line Interface**:
- Multiple modes: search, graph generation, program output, validation
- Usage: `lightgrep [options] pattern_file [input_files...]`

## Code Organization Patterns

### Encoding Support

**Encoder/Decoder Architecture:**
- Factory pattern for creating encoding handlers
- Support for transformation chains (XOR → ROT13 → UTF-8)
- ICU integration for comprehensive Unicode support
- Located in `include/encoders/` and `include/decoders/`

### Error Handling

- C API uses return codes and error handling via `lg_get_error()`
- Internal C++ code uses exceptions
- Error types defined in `include/errors.h`

### Memory Management

- C API uses opaque handles for memory safety
- Internal smart pointers and RAII patterns
- No global state, thread-safe design

## Testing Guidelines

**Test Structure:**
- Unit tests in `test/` directory using Catch2 framework
- Test data in `test/data/`
- Automated tests run with parallel execution support
- Comprehensive coverage of parsing, compilation, and search functionality

**Performance Tests:**
- Benchmarks in `test/benchmarks/`
- Performance regression testing in `pytest/`
- Profiling support with optional Google Profiler integration

## Development Workflow

1. Use Autotools for building and testing
2. Create a decomposed development plan for how to implement the desired changes. Create a new branch with a brief moniker to signify the desired change.
3. Use Test-Driven Development to make the changes as a series of small commits, where a unit test is updated or created to express an envisioned new unit of functionality as part of the current development plan. The unit test should be marked to fail with Catch2's "[!shouldfail]" tag. For tests of new classes or functions, enough of the new code should be stubbed out so that the project compiles and the tests run.
4. Once the initial test change builds and passes (using `make -j8 check`), commit the code. The commit message should begin with "t - " followed by a helpful yet terse description of the test. "t - " is shorthand to code reviewers that the commit involves changes to test code.
5. Change the test to remove the "[!shouldfail]" tag, then implement the behavior change that's embodied by the unit test. Run the tests with `make -j8 check`
6. Once the tests build and pass, commit the changes with a message that begins with "f - ", where this prefix is shorthand for "functional change".
7. Now review the commits adding the unit test and implementing the behavior change. Can the code be improvded? If so, please do so with one or more commits. The commit messages should start with "r -" where 'r' denotes the commit involved a refactoring. When refactoring, it's okay to making syntactic changes to both the test and the actual code, but do not make behavioral changes to both of the tests and tested code in the same commit.
8. With the desired functional change implemented and refactored, move onto the next phase in your plan, per (2).

In general for the developer's workflow:
* ALWAYS run `make -j8 check` before committing changes. The code must compile and all tests must pass at each commit, both for hygiene and to support future regression analysis like "git bisect".
* Do not introduce compiler warnings.
* Test with multiple encodings and binary data
* Validate patterns using `lightgrep -c validate`
* The individual commits should be easy for a human developer to read and review.
* Each commit should qualify as either a discrete testing change ("t - "), a functional change ("f - "), or a refactoring change ("r - ").
* Prefer the use of std::vector and sequential memory accesses in order to provide good performance and memory locality.
* Use modern C++ techniques and idioms that are already in the codebase. Feel free to use the full range of the C++ standard library for C++17.
* Do not eliminate tests or change a larger number of tests unless specifically asked to do so as part of a large refactoring.

## Language Bindings

**Java**: Complete JNI wrapper with Maven build system in `src/java/`
**Python**: Ctypes-based wrapper in `pylightgrep/`

Both bindings provide high-level interfaces while maintaining access to core engine features.
