# Userspace SCTP stack (RFC 9260)
#
# Every artifact lands under $(BUILD); nothing is written next to the sources.
# Run `make help` for the target list.

# ---- toolchain -------------------------------------------------------------
CXX      ?= g++
AR       ?= ar
CXXSTD   := -std=c++17
WARN     := -Wall -Wextra
OPT      ?= -O2
SANITIZE ?=

# include/ is the public API, src/ holds internal headers (serialize, checksum).
INCLUDES := -Iinclude -Isrc

# libcrypto supplies HMAC-SHA-256 for the State Cookie MAC (RFC 9260 5.1.3) and
# the CSPRNG behind the cookie secret. It is confined to src/state_cookie.cpp
# and src/secure_random.cpp: no header under include/ or src/ includes an
# OpenSSL header, so anything linking libsctp.a needs this flag but not
# OpenSSL's include path. Overridable for the Windows build, which has to reach
# BCryptGenRandom instead.
CRYPTO_LIBS ?= -lcrypto

CXXFLAGS  = $(CXXSTD) $(WARN) $(OPT) $(SANITIZE) $(INCLUDES) -pthread
# $(LIB) precedes $(LDFLAGS) in the link rules below, so -lcrypto resolves
# after libsctp.a - the order a static archive requires.
LDFLAGS   = -pthread $(SANITIZE) $(CRYPTO_LIBS)

# ---- layout ----------------------------------------------------------------
# BUILD is overridden by the asan target, so everything derived from it uses
# recursive (=) assignment to re-expand.
BUILD ?= build

LIB        = $(BUILD)/libsctp.a
LIB_SRCS  := $(wildcard src/*.cpp)
LIB_OBJS   = $(LIB_SRCS:%.cpp=$(BUILD)/%.o)

EX_SRCS   := $(wildcard examples/*.cpp)
EX_BINS    = $(EX_SRCS:%.cpp=$(BUILD)/%)

TEST_SRCS := $(wildcard tests/*.cpp)
TEST_BINS  = $(TEST_SRCS:%.cpp=$(BUILD)/%)

FUZZ_SRCS := $(wildcard fuzz/*.cpp)
FUZZ_BINS  = $(FUZZ_SRCS:%.cpp=$(BUILD)/%)
FUZZ_TIME ?= 60
# clang otherwise finds GCC's static libstdc++.a ahead of the shared one, and
# that fails to link alongside the sanitizer runtimes.
FUZZ_LDFLAGS ?= -L/usr/lib

DEPS       = $(LIB_OBJS:.o=.d) $(EX_BINS:%=%.d) $(TEST_BINS:%=%.d) $(FUZZ_BINS:%=%.d)

.PHONY: all lib test run asan tsan fuzz fuzz-run clean help
.DEFAULT_GOAL := all

all: $(LIB) $(EX_BINS) $(TEST_BINS)

lib: $(LIB)

# ---- rules -----------------------------------------------------------------
$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

# Single-translation-unit binaries linked against the static library.
$(BUILD)/examples/%: examples/%.cpp $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP $< $(LIB) -o $@ $(LDFLAGS)

$(BUILD)/tests/%: tests/%.cpp $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP $< $(LIB) -o $@ $(LDFLAGS)

# libFuzzer supplies main(); the library is built with fuzzer-no-link so its
# coverage is traced too.
$(BUILD)/fuzz/%: fuzz/%.cpp $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -MMD -MP $< $(LIB) -o $@ $(FUZZ_LDFLAGS) $(LDFLAGS)

# ---- actions ---------------------------------------------------------------
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "=== $$t"; \
		$$t || exit 1; \
	done

run: $(BUILD)/examples/loopback
	@$<

# Rebuilds into build/asan so sanitized and plain objects never mix.
asan:
	@$(MAKE) --no-print-directory \
		BUILD=$(BUILD)/asan \
		OPT="-O1 -g -fno-omit-frame-pointer" \
		SANITIZE="-fsanitize=address,undefined" \
		test run

# TSan cannot share a binary with ASan, so it gets a tree of its own.
tsan:
	@$(MAKE) --no-print-directory \
		BUILD=$(BUILD)/tsan \
		OPT="-O1 -g -fno-omit-frame-pointer" \
		SANITIZE="-fsanitize=thread" \
		test run

# libFuzzer is clang-only. Each target runs FUZZ_TIME seconds; its corpus
# persists under build/fuzz/corpus and grows across runs.
fuzz:
	@$(MAKE) --no-print-directory \
		BUILD=$(BUILD)/fuzz \
		CXX=clang++ \
		OPT="-O1 -g -fno-omit-frame-pointer" \
		SANITIZE="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined" \
		fuzz-run

fuzz-run: $(FUZZ_BINS)
	@for f in $(FUZZ_BINS); do \
		echo "=== $$f"; \
		mkdir -p $(BUILD)/corpus/$$(basename $$f) $(BUILD)/crashes; \
		$$f -max_total_time=$(FUZZ_TIME) -artifact_prefix=$(BUILD)/crashes/ \
			$(BUILD)/corpus/$$(basename $$f) || exit 1; \
	done

clean:
	rm -rf $(BUILD)

help:
	@echo "make            build library, examples and tests into $(BUILD)/"
	@echo "make lib        build $(LIB) only"
	@echo "make test       build and run wire-conformance tests"
	@echo "make run        run the loopback example"
	@echo "make asan       rebuild under ASan+UBSan into $(BUILD)/asan, run tests + example"
	@echo "make tsan       rebuild under TSan into $(BUILD)/tsan, run tests + example"
	@echo "make fuzz       build libFuzzer targets with clang into $(BUILD)/fuzz, run each FUZZ_TIME s"
	@echo "make clean      remove $(BUILD)/"
	@echo ""
	@echo "Overrides: CXX=clang++  OPT=-O0  BUILD=/tmp/out  FUZZ_TIME=600"

-include $(DEPS)
