#!/usr/bin/env python3
"""
gen_hashes.py — DJB2 Hash Constant Generator for PhantomLDAP

Computes DJB2 hashes for all Windows module names and API function names
used by PhantomLDAP's dynamic resolution engine, and writes the results
to a C header file.

Usage:
    python3 scripts/gen_hashes.py [--output include/dynamic_resolve.h]
    python3 scripts/gen_hashes.py --verify    # Compare against hardcoded values
    python3 scripts/gen_hashes.py --table     # Print markdown table

Author:  PhantomLDAP Project
Version: 1.0.0
"""

import sys
import argparse
import re
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# DJB2 Hash Implementation
# Must match the C implementation in src/core/dynamic_resolve.c exactly.
# ---------------------------------------------------------------------------

def djb2(s: str, case_insensitive: bool = False) -> int:
    """
    Compute the DJB2 hash of a string.
    
    Algorithm: hash(n+1) = hash(n) * 33 + char(n)
    Initial hash value: 5381
    Result: 32-bit unsigned integer
    
    Args:
        s:                Input string
        case_insensitive: If True, lowercase the string before hashing
    
    Returns:
        32-bit DJB2 hash value
    """
    if case_insensitive:
        s = s.lower()
    
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF  # (h * 33 + c) mod 2^32
    return h


def djb2_wide(s: str, case_insensitive: bool = False) -> int:
    """
    Compute DJB2 hash of a wide string (WCHAR -> lower byte only).
    Matches phantom_hash_unicode() in dynamic_resolve.c.
    
    For ASCII module/function names, this produces the same result as djb2().
    """
    return djb2(s, case_insensitive)


# ---------------------------------------------------------------------------
# Hash Target Definitions
# ---------------------------------------------------------------------------

# Module names (compared case-insensitively against BaseDllName in PEB)
MODULE_NAMES = {
    "PHANTOM_HASH_WLDAP32":     ("wldap32.dll",  True),
    "PHANTOM_HASH_KERNEL32":    ("kernel32.dll",  True),
    "PHANTOM_HASH_NTDLL":       ("ntdll.dll",     True),
    "PHANTOM_HASH_NETAPI32":    ("netapi32.dll",  True),
}

# wldap32.dll exported function names (case-sensitive — exact export names)
WLDAP32_FUNCTIONS = {
    "PHANTOM_HASH_ldap_initW":                  ("ldap_initW",                   False),
    "PHANTOM_HASH_ldap_set_option":              ("ldap_set_option",               False),
    "PHANTOM_HASH_ldap_get_option":              ("ldap_get_option",               False),
    "PHANTOM_HASH_ldap_connect":                 ("ldap_connect",                  False),
    "PHANTOM_HASH_ldap_bind_sW":                 ("ldap_bind_sW",                  False),
    "PHANTOM_HASH_ldap_unbind":                  ("ldap_unbind",                   False),
    "PHANTOM_HASH_ldap_search_ext_sW":           ("ldap_search_ext_sW",            False),
    "PHANTOM_HASH_ldap_count_entries":           ("ldap_count_entries",            False),
    "PHANTOM_HASH_ldap_first_entry":             ("ldap_first_entry",              False),
    "PHANTOM_HASH_ldap_next_entry":              ("ldap_next_entry",               False),
    "PHANTOM_HASH_ldap_get_valuesW":             ("ldap_get_valuesW",              False),
    "PHANTOM_HASH_ldap_get_values_lenW":         ("ldap_get_values_lenW",          False),
    "PHANTOM_HASH_ldap_count_valuesW":           ("ldap_count_valuesW",            False),
    "PHANTOM_HASH_ldap_count_values_len":        ("ldap_count_values_len",         False),
    "PHANTOM_HASH_ldap_value_freeW":             ("ldap_value_freeW",              False),
    "PHANTOM_HASH_ldap_value_free_len":          ("ldap_value_free_len",           False),
    "PHANTOM_HASH_ldap_msgfree":                 ("ldap_msgfree",                  False),
    "PHANTOM_HASH_ldap_get_dnW":                 ("ldap_get_dnW",                  False),
    "PHANTOM_HASH_ldap_memfreeW":                ("ldap_memfreeW",                 False),
    "PHANTOM_HASH_ldap_first_attributeW":        ("ldap_first_attributeW",         False),
    "PHANTOM_HASH_ldap_next_attributeW":         ("ldap_next_attributeW",          False),
    "PHANTOM_HASH_ber_free":                     ("ber_free",                      False),
    "PHANTOM_HASH_ldap_create_page_controlW":    ("ldap_create_page_controlW",     False),
    "PHANTOM_HASH_ldap_parse_page_controlW":     ("ldap_parse_page_controlW",      False),
    "PHANTOM_HASH_ldap_parse_resultW":           ("ldap_parse_resultW",            False),
    "PHANTOM_HASH_ldap_controls_freeA":          ("ldap_controls_freeA",           False),
    "PHANTOM_HASH_ldap_err2stringW":             ("ldap_err2stringW",              False),
}

# kernel32.dll exported function names (case-sensitive)
KERNEL32_FUNCTIONS = {
    "PHANTOM_HASH_HeapAlloc":           ("HeapAlloc",           False),
    "PHANTOM_HASH_HeapFree":            ("HeapFree",            False),
    "PHANTOM_HASH_HeapReAlloc":         ("HeapReAlloc",         False),
    "PHANTOM_HASH_GetProcessHeap":      ("GetProcessHeap",      False),
    "PHANTOM_HASH_LoadLibraryW":        ("LoadLibraryW",        False),
    "PHANTOM_HASH_GetProcAddress":      ("GetProcAddress",      False),
    "PHANTOM_HASH_WideCharToMultiByte": ("WideCharToMultiByte", False),
    "PHANTOM_HASH_MultiByteToWideChar": ("MultiByteToWideChar", False),
    "PHANTOM_HASH_lstrlenW":            ("lstrlenW",            False),
}

ALL_GROUPS = [
    ("Module Names (case-insensitive)", MODULE_NAMES),
    ("wldap32.dll Exports",             WLDAP32_FUNCTIONS),
    ("kernel32.dll Exports",            KERNEL32_FUNCTIONS),
]


# ---------------------------------------------------------------------------
# Header Template
# ---------------------------------------------------------------------------

HEADER_SECTION_MODULE = """
/* =========================================================================
 * Pre-computed DJB2 Hashes — Module Names (case-insensitive)
 *
 * Generated by: python3 scripts/gen_hashes.py
 * Timestamp:    {timestamp}
 * Algorithm:    djb2 (hash * 33 + c, seed = 5381, case-insensitive)
 * ========================================================================= */
"""

HEADER_SECTION_WLDAP = """
/* =========================================================================
 * Pre-computed DJB2 Hashes — wldap32.dll Exports (case-sensitive)
 * ========================================================================= */
"""

HEADER_SECTION_K32 = """
/* =========================================================================
 * Pre-computed DJB2 Hashes — kernel32.dll Exports (case-sensitive)
 * ========================================================================= */
"""


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def format_define(name: str, value: int, original: str, case_insensitive: bool) -> str:
    """Format a single #define with hex value and comment."""
    ci_note = "(case-insensitive)" if case_insensitive else ""
    return f'#define {name:<50s} 0x{value:08X}UL    /**< djb2("{original}") {ci_note} */'


def generate_defines(group: dict) -> list[str]:
    """Compute and format all #defines for a hash group."""
    lines = []
    for macro_name, (string, case_insensitive) in sorted(group.items()):
        h = djb2(string, case_insensitive)
        lines.append(format_define(macro_name, h, string, case_insensitive))
    return lines


def print_markdown_table(groups: list) -> None:
    """Print all hashes as a GitHub-flavored markdown table."""
    print("| Macro Name | Input String | Hash (hex) | Case Insensitive |")
    print("|:-----------|:-------------|:----------:|:----------------:|")
    for section_name, group in groups:
        print(f"| **{section_name}** | | | |")
        for macro_name, (string, ci) in sorted(group.items()):
            h = djb2(string, ci)
            ci_str = "✓" if ci else ""
            print(f"| `{macro_name}` | `{string}` | `0x{h:08X}` | {ci_str} |")
    print()


def verify_against_header(header_path: Path) -> bool:
    """
    Parse the existing header and verify computed hashes match.
    
    Returns True if all values match, False if any discrepancy found.
    """
    if not header_path.exists():
        print(f"[ERROR] Header not found: {header_path}", file=sys.stderr)
        return False
    
    content = header_path.read_text(encoding='utf-8')
    pattern = re.compile(r'#define\s+(PHANTOM_HASH_\w+)\s+0x([0-9A-Fa-f]+)UL')
    
    all_groups_flat = {}
    for _, group in ALL_GROUPS:
        all_groups_flat.update(group)
    
    mismatches = []
    not_found = []
    verified = 0
    
    for macro, value_str in pattern.findall(content):
        if macro not in all_groups_flat:
            continue
        string, ci = all_groups_flat[macro]
        computed = djb2(string, ci)
        found = int(value_str, 16)
        if computed != found:
            mismatches.append((macro, string, found, computed))
        else:
            verified += 1
    
    for macro, (string, ci) in all_groups_flat.items():
        if macro not in content:
            not_found.append(macro)
    
    print(f"[VERIFY] Checked {verified} hash constants")
    
    if mismatches:
        print(f"[FAIL]  {len(mismatches)} MISMATCHES FOUND:", file=sys.stderr)
        for macro, string, expected, computed in mismatches:
            print(f"  {macro}: header=0x{expected:08X}, computed=0x{computed:08X} (input='{string}')",
                  file=sys.stderr)
        return False
    
    if not_found:
        print(f"[WARN]  {len(not_found)} constants not found in header:")
        for m in not_found:
            print(f"  {m}")
    
    print(f"[OK]    All {verified} hash constants verified successfully.")
    return True


def update_header(header_path: Path) -> None:
    """
    Update the dynamic_resolve.h header with freshly computed hash values.
    
    Only modifies the #define lines — all other content is preserved.
    """
    if not header_path.exists():
        print(f"[ERROR] Header not found: {header_path}", file=sys.stderr)
        sys.exit(1)
    
    content = header_path.read_text(encoding='utf-8')
    
    # Build a mapping of all macros to their new values
    all_updates = {}
    for _, group in ALL_GROUPS:
        for macro, (string, ci) in group.items():
            all_updates[macro] = djb2(string, ci)
    
    # Replace each #define value in-place
    def replace_hash(m: re.Match) -> str:
        macro = m.group(1)
        if macro in all_updates:
            new_val = all_updates[macro]
            return m.group(0).replace(m.group(2), f'{new_val:08X}')
        return m.group(0)
    
    pattern = re.compile(r'(#define\s+PHANTOM_HASH_\w+\s+0x)([0-9A-Fa-f]{8})UL')
    new_content = pattern.sub(replace_hash, content)
    
    if new_content == content:
        print("[INFO] No changes required — all hashes are already up to date.")
        return
    
    header_path.write_text(new_content, encoding='utf-8')
    print(f"[OK]  Updated {header_path}")
    
    # Print summary of changes
    updated = sum(1 for m in pattern.finditer(content) if m.group(1).split()[0].replace('#define', '').strip() in all_updates)
    print(f"[OK]  Updated {len(all_updates)} hash constants")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PhantomLDAP DJB2 Hash Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/gen_hashes.py              # Update include/dynamic_resolve.h
  python3 scripts/gen_hashes.py --verify     # Verify existing values
  python3 scripts/gen_hashes.py --table      # Print markdown table
  python3 scripts/gen_hashes.py --compute wldap32.dll  # Hash a specific string
        """
    )
    parser.add_argument(
        "--output", "-o",
        default="include/dynamic_resolve.h",
        help="Path to dynamic_resolve.h to update (default: include/dynamic_resolve.h)"
    )
    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify existing hash values without modifying the file"
    )
    parser.add_argument(
        "--table", "-t",
        action="store_true",
        help="Print all hashes as a markdown table and exit"
    )
    parser.add_argument(
        "--compute", "-c",
        metavar="STRING",
        help="Compute and print the DJB2 hash of a specific string"
    )
    parser.add_argument(
        "--case-insensitive",
        action="store_true",
        help="Use case-insensitive hashing with --compute"
    )
    args = parser.parse_args()
    
    # One-off hash computation
    if args.compute:
        h = djb2(args.compute, args.case_insensitive)
        print(f'djb2("{args.compute}", ci={args.case_insensitive}) = 0x{h:08X}UL  ({h})')
        print(f'#define PHANTOM_HASH_???  0x{h:08X}UL')
        return
    
    # Print markdown table
    if args.table:
        print_markdown_table(ALL_GROUPS)
        return
    
    header_path = Path(args.output)
    
    # Verify mode
    if args.verify:
        ok = verify_against_header(header_path)
        sys.exit(0 if ok else 1)
    
    # Default: update header
    print(f"[*] PhantomLDAP Hash Generator v1.0.0")
    print(f"[*] Updating: {header_path}")
    print()
    
    # Print computed values for reference
    for section_name, group in ALL_GROUPS:
        print(f"  [{section_name}]")
        for macro, (string, ci) in sorted(group.items()):
            h = djb2(string, ci)
            print(f"    {macro:<50s} = 0x{h:08X}")
        print()
    
    update_header(header_path)


if __name__ == "__main__":
    main()
