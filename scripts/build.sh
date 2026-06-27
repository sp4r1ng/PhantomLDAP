#!/usr/bin/env bash
# ===========================================================================
# build.sh — PhantomLDAP Linux Cross-Compilation Script
#
# Builds all BOF modules using the MinGW-w64 cross-compiler.
# Equivalent to running 'make all' but provides richer diagnostics,
# color output, and does not require GNU Make to be installed.
#
# Usage:
#   ./scripts/build.sh               Build all modules
#   ./scripts/build.sh --clean       Remove build/ directory
#   ./scripts/build.sh enum_spn      Build a single module
#   ./scripts/build.sh --verify      Build + run symbol validation
#   ./scripts/build.sh --help        Show this help
#
# Requirements:
#   x86_64-w64-mingw32-gcc (apt: mingw-w64)
#   Python 3.x (for hash verification)
#
# Author:  PhantomLDAP Project
# Version: 1.0.0
# ===========================================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Toolchain ────────────────────────────────────────────────────────────────
CC="x86_64-w64-mingw32-gcc"
LD="x86_64-w64-mingw32-ld"
NM="x86_64-w64-mingw32-nm"

# ── Directories ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"
SRC_CORE="$ROOT_DIR/src/core"
SRC_MOD="$ROOT_DIR/src/modules"
INC="$ROOT_DIR/include"

# ── Compiler Flags ────────────────────────────────────────────────────────────
CFLAGS=(
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-implicit-function-declaration
    -nostdlib
    -masm=intel
    -fno-builtin
    -fno-stack-protector
    -ffunction-sections
    -fdata-sections
    -O2
    "-I$INC"
    -D_WIN64
    -DUNICODE
    -D_UNICODE
)

# ── Module List ───────────────────────────────────────────────────────────────
MODULES=(
    enum_admins
    enum_spn
    enum_asrep
    enum_computers
    enum_trusts
    enum_gpo
    enum_acl
    ldap_query
)

# ── Helper Functions ──────────────────────────────────────────────────────────

log_ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
log_cc()   { echo -e "${CYAN}[CC]${NC}  $*"; }
log_ld()   { echo -e "${CYAN}[LD]${NC}  $*"; }
log_err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WRN]${NC} $*"; }
log_info() { echo -e "${BOLD}[*]${NC}   $*"; }

print_banner() {
    echo -e "${CYAN}"
    echo ' ____  _           _                _   _     ____    _    ____'
    echo '|  _ \| |__   __ _| |_ ___  _ __ | | | |   |  _ \  / \  |  _ \'
    echo '| |_) | '"'"'_ \ / _` | __/ _ \| '"'"'_ \| | | |   | | | |/ _ \ | |_) |'
    echo '|  __/| | | | (_| | || (_) | | | | |_| |   | |_| / ___ \|  __/'
    echo '|_|   |_| |_|\__,_|\__\___/|_| |_|\___/    |____/_/   \_\_|'
    echo -e "  PhantomLDAP v1.0.0 | Build Script${NC}"
    echo ""
}

check_toolchain() {
    local missing=0
    for tool in "$CC" "$LD" "$NM"; do
        if ! command -v "$tool" &>/dev/null; then
            log_err "Toolchain not found: $tool"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        echo ""
        echo "Install MinGW-w64: sudo apt-get install -y mingw-w64"
        exit 1
    fi
    log_ok "Toolchain: $($CC --version | head -1)"
}

clean() {
    log_info "Cleaning $BUILD_DIR ..."
    rm -rf "$BUILD_DIR"
    log_ok "Clean complete."
}

build_core() {
    mkdir -p "$BUILD_DIR/core"

    local core_files=( dynamic_resolve ldap_ops output )
    for f in "${core_files[@]}"; do
        local src="$SRC_CORE/$f.c"
        local obj="$BUILD_DIR/core/$f.o"
        log_cc "$f.c"
        "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
    done
    log_ok "Core objects compiled."
}

build_module() {
    local mod="$1"
    local src="$SRC_MOD/$mod.c"
    local tmp="$BUILD_DIR/${mod}_tmp.o"
    local out="$BUILD_DIR/$mod.o"

    if [[ ! -f "$src" ]]; then
        log_err "Module source not found: $src"
        return 1
    fi

    log_cc "$mod.c"
    "$CC" "${CFLAGS[@]}" -c "$src" -o "$tmp"

    log_ld "Partial link → $mod.o"
    "$LD" -r -o "$out" \
        "$tmp" \
        "$BUILD_DIR/core/dynamic_resolve.o" \
        "$BUILD_DIR/core/ldap_ops.o" \
        "$BUILD_DIR/core/output.o"

    rm -f "$tmp"

    local size
    size=$(wc -c < "$out")
    log_ok "$mod.o  ($size bytes)"
}

verify_bofs() {
    local fail=0
    echo ""
    log_info "Running BOF validation checks..."
    echo ""
    printf "  %-30s %-10s %-10s %-12s\n" "Module" "go() found" "IAT clean" "Size"
    printf "  %s\n" "------------------------------------------------------------"

    for mod in "${MODULES[@]}"; do
        local obj="$BUILD_DIR/$mod.o"
        [[ -f "$obj" ]] || { printf "  %-30s MISSING\n" "$mod.o"; fail=1; continue; }

        # Check go() entry point
        local has_go
        has_go=$("$NM" "$obj" 2>/dev/null | grep -c "T go$" || true)
        local go_mark
        [[ "$has_go" -gt 0 ]] && go_mark="${GREEN}✓${NC}" || { go_mark="${RED}✗${NC}"; fail=1; }

        # Check for static LDAP IAT imports
        local iat_hits
        iat_hits=$("$NM" "$obj" 2>/dev/null | grep -ci "__imp_ldap" || true)
        local iat_mark
        [[ "$iat_hits" -eq 0 ]] && iat_mark="${GREEN}✓${NC}" || { iat_mark="${RED}✗ ($iat_hits)${NC}"; fail=1; }

        local size
        size=$(wc -c < "$obj")
        printf "  %-30s " "$mod.o"
        echo -e "$go_mark         $iat_mark          ${size}B"
    done

    echo ""
    if [[ $fail -eq 0 ]]; then
        log_ok "All validation checks passed."
    else
        log_err "One or more checks FAILED. Review output above."
        exit 1
    fi
}

verify_hashes() {
    if command -v python3 &>/dev/null; then
        log_info "Verifying DJB2 hash constants..."
        python3 "$ROOT_DIR/scripts/gen_hashes.py" --verify \
            --output "$INC/dynamic_resolve.h" \
            && log_ok "Hash constants verified." \
            || log_warn "Hash mismatch detected — run: make hashes"
    else
        log_warn "Python 3 not found — skipping hash verification."
    fi
}

print_summary() {
    echo ""
    echo -e "${BOLD}================================================================${NC}"
    echo -e "${BOLD} PhantomLDAP Build Complete${NC}"
    echo -e "${BOLD}================================================================${NC}"
    printf "  %-35s %s\n" "Module" "Size"
    printf "  %s\n" "-----------------------------------------------"
    for mod in "${MODULES[@]}"; do
        local obj="$BUILD_DIR/$mod.o"
        if [[ -f "$obj" ]]; then
            printf "  %-35s %s bytes\n" "$mod.o" "$(wc -c < "$obj")"
        fi
    done
    echo ""
    log_info "Load cna/phantom_ldap.cna in Cobalt Strike to use."
    echo ""
}

show_help() {
    echo "Usage: $0 [OPTIONS] [MODULE]"
    echo ""
    echo "Options:"
    echo "  --clean     Remove build directory"
    echo "  --verify    Build and run validation checks"
    echo "  --help      Show this help"
    echo ""
    echo "Module (optional — builds all if omitted):"
    for m in "${MODULES[@]}"; do echo "  $m"; done
    exit 0
}

# ── Main ──────────────────────────────────────────────────────────────────────

print_banner

# Argument parsing
DO_VERIFY=0
TARGET_MODULE=""

for arg in "$@"; do
    case "$arg" in
        --clean)  check_toolchain; clean; exit 0 ;;
        --verify) DO_VERIFY=1 ;;
        --help)   show_help ;;
        --*)      log_err "Unknown option: $arg"; exit 1 ;;
        *)        TARGET_MODULE="$arg" ;;
    esac
done

check_toolchain
verify_hashes

# Build
if [[ -n "$TARGET_MODULE" ]]; then
    # Single module build
    mkdir -p "$BUILD_DIR"
    build_core
    build_module "$TARGET_MODULE"
else
    # Full build
    mkdir -p "$BUILD_DIR"
    build_core
    for mod in "${MODULES[@]}"; do
        build_module "$mod"
    done
fi

[[ $DO_VERIFY -eq 1 ]] && verify_bofs

print_summary
