# Userspace SCTP stack (RFC 9260)
#
# Every artifact lands under $(BUILD); nothing is written next to the sources.
# Run `make help` for the target list.

# ---- toolchain -------------------------------------------------------------
CXX      ?= g++
AR       ?= ar
CXXSTD   := -std=c++23
WARN     := -Wall -Wextra
OPT      ?= -O2
SANITIZE ?=

# include/ is the public API; src/ holds the internal headers. Both are split
# into the same modules, one directory each.
INCLUDES := -Iinclude -Isrc

CXXFLAGS  = $(CXXSTD) $(WARN) $(OPT) $(SANITIZE) $(INCLUDES) -pthread
LDFLAGS   = -pthread $(SANITIZE)

# ---- layout ----------------------------------------------------------------
BUILD ?= build

LIB       := $(BUILD)/libsctp.a
LIB_OBJS  := $(patsubst %.cpp,$(BUILD)/%.o,$(wildcard src/*/*.cpp))
EX_BINS   := $(patsubst %.cpp,$(BUILD)/%,$(wildcard examples/*.cpp))
TEST_BINS := $(patsubst %.cpp,$(BUILD)/%,$(wildcard tests/*/*.cpp))
FUZZ_BINS := $(patsubst %.cpp,$(BUILD)/%,$(wildcard fuzz/*.cpp))
DEPS      := $(LIB_OBJS:.o=.d) $(addsuffix .d,$(EX_BINS) $(TEST_BINS) $(FUZZ_BINS))

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

# Single-translation-unit binaries linked against the static library. Tests
# also see tests/support.hpp; private keeps that off the library objects.
$(TEST_BINS): private INCLUDES += -Itests

$(EX_BINS) $(TEST_BINS): $(BUILD)/%: %.cpp $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP $< $(LIB) -o $@ $(LDFLAGS)

# libFuzzer supplies main(); the library is built with fuzzer-no-link so its
# coverage is traced too. Without -L/usr/lib, clang finds GCC's static
# libstdc++.a ahead of the shared one, and that fails to link alongside the
# sanitizer runtimes.
FUZZ_LDFLAGS ?= -L/usr/lib

$(FUZZ_BINS): $(BUILD)/%: %.cpp $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -MMD -MP $< $(LIB) -o $@ $(FUZZ_LDFLAGS) $(LDFLAGS)

# ---- actions ---------------------------------------------------------------
# Every binary runs even after one fails, so a failing RFC requirement does not
# hide the rest; the failures are listed at the end.
test: $(TEST_BINS)
	@failed=""; for t in $(TEST_BINS); do \
		echo "=== $$t"; \
		$$t || failed="$$failed $$t"; \
	done; \
	if [ -n "$$failed" ]; then echo; echo "FAILED:$$failed"; exit 1; fi

run: $(BUILD)/examples/loopback
	@$<

# Instrumented builds get trees of their own: ASan and TSan cannot share a
# binary, and neither mixes with plain objects. -k still runs the example when
# a test fails.
INSTRUMENTED := --no-print-directory OPT="-O1 -g -fno-omit-frame-pointer"

asan:
	@$(MAKE) $(INSTRUMENTED) -k BUILD=$(BUILD)/asan SANITIZE="-fsanitize=address,undefined" test run

tsan:
	@$(MAKE) $(INSTRUMENTED) -k BUILD=$(BUILD)/tsan SANITIZE=-fsanitize=thread test run

# libFuzzer is clang-only. Each target runs FUZZ_TIME seconds; its corpus
# persists under build/fuzz/corpus and grows across runs.
FUZZ_TIME ?= 60

fuzz:
	@$(MAKE) $(INSTRUMENTED) BUILD=$(BUILD)/fuzz CXX=clang++ \
		SANITIZE="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined" fuzz-run

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
	@echo "make test       build and run the tests, listing any that fail"
	@echo "make run        run the loopback example"
	@echo "make asan       rebuild under ASan+UBSan into $(BUILD)/asan, run tests + example"
	@echo "make tsan       rebuild under TSan into $(BUILD)/tsan, run tests + example"
	@echo "make fuzz       build libFuzzer targets with clang into $(BUILD)/fuzz, run each FUZZ_TIME s"
	@echo "make clean      remove $(BUILD)/"
	@echo ""
	@echo "Overrides: CXX=clang++  OPT=-O0  BUILD=/tmp/out  FUZZ_TIME=600"

-include $(DEPS)
