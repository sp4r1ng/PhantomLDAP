##
## PhantomLDAP — Makefile
##
## Builds all BOF modules by partially linking each module's object file with
## the three shared core objects (dynamic_resolve, ldap_ops, output).
##
## Usage:
##   make all           — Build all BOF modules (default)
##   make clean         — Remove all build artifacts
##   make <module>      — Build a specific module (e.g., make enum_spn)
##   make hashes        — Regenerate DJB2 hash constants (requires Python 3)
##   make verify        — Validate BOF symbols (go(), clean IAT) after build
##   make test          — Build and run DJB2 hash unit tests (native exe)
##   make test_peb_walk — Build and run PEB walk validation harness
##   make help          — Print this help message
##
## Targets produced (in build/):
##   enum_admins.o   enum_spn.o   enum_asrep.o   enum_computers.o
##   enum_trusts.o   enum_gpo.o   enum_acl.o     ldap_query.o
##
## Requirements:
##   - MinGW-w64 cross-compiler: x86_64-w64-mingw32-gcc
##   - GNU Make >= 4.0
##   - GNU ld (for partial linking via -r flag)
##   - Python 3.x (for 'make hashes' only)
##
## Cross-compilation notes:
##   The -nostdlib flag prevents MinGW from linking any standard C runtime.
##   BOFs must not rely on CRT initialization — all functions must be
##   called via dynamic resolution or Beacon's import mechanism.
##

# ===========================================================================
# Toolchain Configuration
# ===========================================================================

CC      := x86_64-w64-mingw32-gcc
LD      := x86_64-w64-mingw32-ld
OBJCOPY := x86_64-w64-mingw32-objcopy
PYTHON  := python3

# ===========================================================================
# Directories
# ===========================================================================

SRC_CORE    := src/core
SRC_MODULES := src/modules
INC         := include
BUILD       := build
SCRIPTS     := scripts
DOCS        := docs

# ===========================================================================
# Compiler Flags
# ===========================================================================

# -Wall -Wextra     — Maximum warnings (treat code as warnings until clean)
# -nostdlib         — No CRT; BOFs use Beacon's runtime
# -masm=intel       — Intel ASM syntax for inline assembly (PEB walker)
# -fno-builtin      — Disable compiler built-in function substitution
# -fno-stack-protector  — Disable stack cookies (no CRT for __stack_chk_fail)
# -ffunction-sections   — Each function in its own ELF section
# -fdata-sections       — Each data item in its own ELF section
# -O2               — Optimize for size/speed without debug overhead
# -Wno-unused-parameter — Beacon API parameters may be unused in some modules

CFLAGS := \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -Wno-implicit-function-declaration \
    -nostdlib \
    -masm=intel \
    -fno-builtin \
    -fno-stack-protector \
    -ffunction-sections \
    -fdata-sections \
    -O2 \
    -I$(INC) \
    -D_WIN64 \
    -DUNICODE \
    -D_UNICODE

# Partial link flags (combine multiple .o into one .o without resolving externals)
LDFLAGS_PARTIAL := -r

# ===========================================================================
# Source Files
# ===========================================================================

# Core source files linked into every BOF module
CORE_SOURCES := \
    $(SRC_CORE)/dynamic_resolve.c \
    $(SRC_CORE)/ldap_ops.c \
    $(SRC_CORE)/output.c

# Core object files (intermediate, per-module copies)
# Each module gets its own compiled core to avoid symbol collisions
CORE_OBJECTS_BASE := \
    dynamic_resolve.o \
    ldap_ops.o \
    output.o

# Module source files
MODULE_SOURCES := \
    $(SRC_MODULES)/enum_admins.c \
    $(SRC_MODULES)/enum_spn.c \
    $(SRC_MODULES)/enum_asrep.c \
    $(SRC_MODULES)/enum_computers.c \
    $(SRC_MODULES)/enum_trusts.c \
    $(SRC_MODULES)/enum_gpo.c \
    $(SRC_MODULES)/enum_acl.c \
    $(SRC_MODULES)/ldap_query.c

# Final BOF output files
BOF_TARGETS := \
    $(BUILD)/enum_admins.o \
    $(BUILD)/enum_spn.o \
    $(BUILD)/enum_asrep.o \
    $(BUILD)/enum_computers.o \
    $(BUILD)/enum_trusts.o \
    $(BUILD)/enum_gpo.o \
    $(BUILD)/enum_acl.o \
    $(BUILD)/ldap_query.o

# ===========================================================================
# Default Target
# ===========================================================================

.PHONY: all clean help hashes dirs info

all: dirs $(BOF_TARGETS)
	@echo ""
	@echo "================================================================"
	@echo " PhantomLDAP Build Complete"
	@echo "================================================================"
	@echo " BOF files in: $(BUILD)/"
	@for f in $(BOF_TARGETS); do \
	    printf "  %-40s %s bytes\n" "$$f" "$$(wc -c < $$f 2>/dev/null || echo '?')"; \
	done
	@echo "================================================================"
	@echo " Load $(shell pwd)/cna/phantom_ldap.cna in Cobalt Strike"
	@echo "================================================================"

# ===========================================================================
# Directory Creation
# ===========================================================================

dirs:
	@mkdir -p $(BUILD)
	@mkdir -p $(BUILD)/core

# ===========================================================================
# Core Object Compilation (shared between modules)
#
# Each core file is compiled once per module invocation of make, but since
# we use pattern rules and intermediate targets, make will cache them within
# a single invocation.
# ===========================================================================

$(BUILD)/core/dynamic_resolve.o: $(SRC_CORE)/dynamic_resolve.c $(INC)/dynamic_resolve.h $(INC)/win_types.h
	@echo "[CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/core/ldap_ops.o: $(SRC_CORE)/ldap_ops.c $(INC)/phantom_ldap.h $(INC)/ldap_types.h
	@echo "[CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/core/output.o: $(SRC_CORE)/output.c $(INC)/phantom_ldap.h
	@echo "[CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Convenience target: compile all core objects
.PHONY: core
core: $(BUILD)/core/dynamic_resolve.o $(BUILD)/core/ldap_ops.o $(BUILD)/core/output.o

# ===========================================================================
# Module Build Rules
#
# Each module is compiled, then partially linked with the three core objects
# to produce a single self-contained .o file that Cobalt Strike can load.
#
# Partial linking (-r) combines multiple object files into one without
# performing full relocation/symbol resolution, preserving the relocatable
# format required by the Beacon loader.
# ===========================================================================

define BUILD_MODULE
$(BUILD)/$(1).o: $(SRC_MODULES)/$(1).c core
	@echo "[CC]  $$<"
	@$(CC) $(CFLAGS) -c $$< -o $(BUILD)/$(1)_mod.o
	@echo "[LD]  Partial link -> $(BUILD)/$(1).o"
	@$(LD) $(LDFLAGS_PARTIAL) -o $(BUILD)/$(1).o \
	    $(BUILD)/$(1)_mod.o \
	    $(BUILD)/core/dynamic_resolve.o \
	    $(BUILD)/core/ldap_ops.o \
	    $(BUILD)/core/output.o
	@rm -f $(BUILD)/$(1)_mod.o
	@echo "[OK]  $(BUILD)/$(1).o ($$(wc -c < $(BUILD)/$(1).o) bytes)"
endef

$(eval $(call BUILD_MODULE,enum_admins))
$(eval $(call BUILD_MODULE,enum_spn))
$(eval $(call BUILD_MODULE,enum_asrep))
$(eval $(call BUILD_MODULE,enum_computers))
$(eval $(call BUILD_MODULE,enum_trusts))
$(eval $(call BUILD_MODULE,enum_gpo))
$(eval $(call BUILD_MODULE,enum_acl))
$(eval $(call BUILD_MODULE,ldap_query))

# ===========================================================================
# Individual Module Shortcuts
# ===========================================================================

.PHONY: enum_admins enum_spn enum_asrep enum_computers enum_trusts enum_gpo enum_acl ldap_query

enum_admins:   $(BUILD)/enum_admins.o
enum_spn:      $(BUILD)/enum_spn.o
enum_asrep:    $(BUILD)/enum_asrep.o
enum_computers: $(BUILD)/enum_computers.o
enum_trusts:   $(BUILD)/enum_trusts.o
enum_gpo:      $(BUILD)/enum_gpo.o
enum_acl:      $(BUILD)/enum_acl.o
ldap_query:    $(BUILD)/ldap_query.o

# ===========================================================================
# Hash Generation
# ===========================================================================

hashes:
	@echo "[PY]  Regenerating DJB2 hash constants..."
	@$(PYTHON) $(SCRIPTS)/gen_hashes.py
	@echo "[OK]  Hash constants written to $(INC)/dynamic_resolve.h"

# ===========================================================================
# Verification — validate BOF symbols post-build
# ===========================================================================

NM := x86_64-w64-mingw32-nm

VERIFY_MODS := enum_admins enum_spn enum_asrep enum_computers \
               enum_trusts enum_gpo enum_acl ldap_query

.PHONY: verify
verify: all
	@echo ""
	@echo "[>>] BOF Symbol Validation"
	@echo "  Module                         go()  IAT-clean  Size"
	@echo "  ----------------------------------------------------------------"
	@fail=0; \
	 for mod in $(VERIFY_MODS); do \
	     obj=$(BUILD)/$$mod.o; \
	     if [ ! -f "$$obj" ]; then \
	         printf "  %-30s MISSING\n" $$mod.o; fail=1; continue; \
	     fi; \
	     go=$$($(NM) $$obj 2>/dev/null | grep -c '^[0-9a-f]* T go$$' || true); \
	     iat=$$($(NM) $$obj 2>/dev/null | grep -ic '__imp_ldap' || true); \
	     sz=$$(wc -c < $$obj); \
	     go_ok="PASS"; [ "$$go" -gt 0 ] || { go_ok="FAIL"; fail=1; }; \
	     iat_ok="PASS"; [ "$$iat" -eq 0 ] || { iat_ok="FAIL ($$iat)"; fail=1; }; \
	     printf "  %-30s %-6s  %-10s %s bytes\n" $$mod.o $$go_ok $$iat_ok $$sz; \
	 done; \
	 echo ""; \
	 if [ $$fail -eq 0 ]; then echo "[OK]  All validation checks passed."; \
	 else echo "[ERR] One or more checks FAILED."; exit 1; fi

# ===========================================================================
# Unit Tests
# ===========================================================================

.PHONY: test test_hash test_peb_walk

## Build and run DJB2 hash unit tests (links against kernel32 — test only)
test: test_hash

test_hash: $(BUILD)/test_hash.exe
	@echo "[RUN] Running DJB2 hash tests..."
	@$(BUILD)/test_hash.exe || (echo "[ERR] test_hash FAILED"; exit 1)

$(BUILD)/test_hash.exe: tests/test_hash.c $(SRC_CORE)/dynamic_resolve.c | $(BUILD)
	@echo "[CC]  tests/test_hash.c (test binary)"
	@$(CC) -I$(INC) -D_WIN64 -DUNICODE -O0 -g \
	    tests/test_hash.c $(SRC_CORE)/dynamic_resolve.c \
	    -o $@ -lkernel32

## Build and run PEB walk validation harness (cross-validates vs GetModuleHandleW)
test_peb_walk: $(BUILD)/test_peb_walk.exe
	@echo "[RUN] Running PEB walk tests..."
	@$(BUILD)/test_peb_walk.exe || (echo "[ERR] test_peb_walk FAILED"; exit 1)

$(BUILD)/test_peb_walk.exe: tests/test_peb_walk.c $(SRC_CORE)/dynamic_resolve.c | $(BUILD)
	@echo "[CC]  tests/test_peb_walk.c (test binary)"
	@$(CC) -I$(INC) -D_WIN64 -DUNICODE -O0 -g \
	    tests/test_peb_walk.c $(SRC_CORE)/dynamic_resolve.c \
	    -o $@ -lkernel32

# ===========================================================================
# Build Info
# ===========================================================================

info:
	@echo "PhantomLDAP Build Configuration"
	@echo "  CC      : $(shell $(CC) --version | head -1)"
	@echo "  CFLAGS  : $(CFLAGS)"
	@echo "  Modules : $(words $(MODULE_SOURCES))"
	@echo "  Output  : $(BUILD)/"

# ===========================================================================
# Clean
# ===========================================================================

clean:
	@echo "[RM]  Cleaning build artifacts..."
	@rm -rf $(BUILD)
	@echo "[OK]  Clean complete."

# ===========================================================================
# Help
# ===========================================================================

help:
	@echo ""
	@echo "PhantomLDAP Build System"
	@echo "========================"
	@echo ""
	@echo "Usage: make [TARGET]"
	@echo ""
	@echo "Build Targets:"
	@echo "  all              Build all BOF modules (default)"
	@echo "  clean            Remove all build artifacts"
	@echo "  core             Compile core objects only"
	@echo "  enum_admins      Build admin enumeration module"
	@echo "  enum_spn         Build SPN/Kerberoasting module"
	@echo "  enum_asrep       Build AS-REP Roasting module"
	@echo "  enum_computers   Build computer enumeration module"
	@echo "  enum_trusts      Build domain trust enumeration module"
	@echo "  enum_gpo         Build GPO enumeration module"
	@echo "  enum_acl         Build DACL analysis module"
	@echo "  ldap_query       Build custom LDAP query module"
	@echo ""
	@echo "Validation Targets:"
	@echo "  verify           Validate all BOF symbols (go() + clean IAT)"
	@echo "  test             Build and run DJB2 hash unit tests"
	@echo "  test_peb_walk    Build and run PEB walk validation harness"
	@echo ""
	@echo "Utility Targets:"
	@echo "  hashes           Regenerate DJB2 hash constants (requires Python 3)"
	@echo "  info             Show build configuration"
	@echo "  help             Show this message"
	@echo ""
	@echo "Requirements:"
	@echo "  - x86_64-w64-mingw32-gcc (MinGW-w64)"
	@echo "  - GNU Make >= 4.0"
	@echo "  - Python 3 (for 'make hashes' only)"
	@echo "  - Wine (optional, for running test binaries on Linux)"
	@echo ""
