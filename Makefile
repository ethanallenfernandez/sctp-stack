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
CXXFLAGS  = $(CXXSTD) $(WARN) $(OPT) $(SANITIZE) $(INCLUDES) -pthread
LDFLAGS   = -pthread $(SANITIZE)

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

DEPS       = $(LIB_OBJS:.o=.d) $(EX_BINS:%=%.d) $(TEST_BINS:%=%.d)

.PHONY: all lib test run asan clean help
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

clean:
	rm -rf $(BUILD)

help:
	@echo "make            build library, examples and tests into $(BUILD)/"
	@echo "make lib        build $(LIB) only"
	@echo "make test       build and run wire-conformance tests"
	@echo "make run        run the loopback example"
	@echo "make asan       rebuild under ASan+UBSan into $(BUILD)/asan, run tests + example"
	@echo "make clean      remove $(BUILD)/"
	@echo ""
	@echo "Overrides: CXX=clang++  OPT=-O0  BUILD=/tmp/out"

-include $(DEPS)
