from __future__ import annotations

import pytest

from ida_pro_mcp.vnext.symbols import (
    close_matches,
    collapse_templates,
    parse_bare_hex,
    parse_offset_expr,
    parse_segment_expr,
    pretty_symbol,
    strip_signature,
    unqualified,
)


@pytest.mark.parametrize(
    ("demangled", "expected"),
    [
        ("public: virtual void __cdecl Foo::bar(int) const", "Foo::bar"),
        ("std::vector<int, std::allocator<int> >::push_back(int const&)", "std::vector<int, std::allocator<int> >::push_back"),
        ("void * __cdecl operator new(unsigned __int64)", "operator new"),
        ("Foo::operator()(int)", "Foo::operator()"),
        ("Foo::operator<(Foo const&) const", "Foo::operator<"),
        ("operator<<(std::ostream&, Foo const&)", "operator<<"),
        ("public: __cdecl Foo::operator bool(void) const", "Foo::operator bool"),
        ("public: static int Foo::count", "Foo::count"),
        ("(anonymous namespace)::helper(int)", "(anonymous namespace)::helper"),
        ("`anonymous namespace'::helper", "`anonymous namespace'::helper"),
        ("non-virtual thunk to Foo::bar(int)", "non-virtual thunk to Foo::bar"),
        ("vtable for Foo", "vtable for Foo"),
        ("foo(int) [clone .cold]", "foo"),
        ("main", "main"),
    ],
)
def test_strip_signature_keeps_only_qualified_name(demangled, expected):
    assert strip_signature(demangled) == expected


def test_collapse_templates_only_when_long():
    short = "std::vector<int>::push_back"
    assert collapse_templates(short) == short
    long = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_construct<char const*>"
    assert collapse_templates(long) == "std::basic_string<…>::_M_construct<…>"
    # operator< is not a template opener
    assert collapse_templates("Foo::operator<" + "x" * 90, 80) == "Foo::operator<" + "x" * 90
    assert pretty_symbol("void __cdecl " + long + "(char const*, char const*)") == "std::basic_string<…>::_M_construct<…>"


def test_unqualified_ignores_scopes_inside_templates():
    assert unqualified("ns::Foo<a::b>::bar") == "bar"
    assert unqualified("main") == "main"


def test_address_expression_parsers():
    assert parse_offset_expr("main+0x10") == ("main", 0x10)
    assert parse_offset_expr("main-16") == ("main", -16)
    assert parse_offset_expr("sub_1000+1C") == ("sub_1000", 0x1C)
    assert parse_offset_expr("Foo::operator+") is None
    assert parse_segment_expr(".text:140001000") == (".text", 0x140001000)
    assert parse_segment_expr("std::foo") is None
    assert parse_bare_hex("123e") == 0x123E
    assert parse_bare_hex("401000h") == 0x401000
    assert parse_bare_hex("main") is None


def test_close_matches_suggests_typos_and_substrings():
    pool = ["check_pw", "main", "puts", "printf", "_start"]
    assert close_matches("chek_pw", pool) == ["check_pw"]
    assert close_matches("print", pool)[0] == "printf"
    assert close_matches("zzzzzz", pool) == []
