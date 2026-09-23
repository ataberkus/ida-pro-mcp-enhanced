from ida_pro_mcp.vnext.function_review import (
    attach_review_views,
    build_cursor_prompt,
    build_mutation_operations,
    format_analysis_summary,
    local_rename_rows,
    lvar_names_from_decompiled,
    parse_local_renames,
    selected_local_renames,
)


SAMPLE = {
    "addr": "0x123e",
    "name": "main",
    "prototype": "int main(int argc, char **argv)",
    "size": 260,
    "error": None,
    "strings": ["Need exactly one argument", "password"],
    "callees": ["puts", "check_pw"],
    "callers": ["_start"],
    "constants": [{"value": 0x401000}],
    "basic_blocks": {"count": 8, "cyclomatic_complexity": 4},
    "decompiled": "int __fastcall main(int a1, char **a2)\n{\n  int v3;\n  return v3;\n}\n",
    "locals": [{"name": "a1", "is_arg": True}, {"name": "v3", "is_arg": False}],
}


def test_summary_and_prompt_include_function_evidence():
    summary = format_analysis_summary(SAMPLE)
    prompt = build_cursor_prompt(SAMPLE, database="crackme03.elf")
    assert "0x123e" in summary
    assert "main" in summary
    assert "puts" in summary
    assert "Need exactly one argument" in summary
    assert "int __fastcall main" in summary
    assert "Database session: `crackme03.elf`" in prompt
    assert 'analysis_run(mode="function")' in prompt
    assert "mutation_preview" in prompt
    assert "Do not mutation_commit until I approve" in prompt
    assert "0x123e" in prompt


def test_local_rows_prefer_decompiler_locals_over_regex():
    rows = local_rename_rows(SAMPLE)
    assert [row["name"] for row in rows] == ["a1", "v3"]
    assert rows[0]["is_arg"] == "1"
    parsed = lvar_names_from_decompiled(SAMPLE["decompiled"])
    assert parsed == ["a1", "a2", "v3"]


def test_parse_and_select_local_renames():
    parsed = parse_local_renames("a1=argc\nv3 -> count\n# skip\nv3=count\nfoo=\n")
    assert parsed == [{"old": "a1", "new": "argc"}, {"old": "v3", "new": "count"}]
    selected = selected_local_renames(
        [{"name": "a1", "new": "argc"}, {"name": "v3", "new": "v3"}, {"name": "a2", "new": ""}]
    )
    assert selected == [{"old": "a1", "new": "argc"}]


def test_mutation_operations_reject_empty_address():
    import pytest

    from ida_pro_mcp.vnext.contracts import ErrorCode, VNextError

    with pytest.raises(VNextError) as exc_info:
        build_mutation_operations(addr="")
    assert exc_info.value.code is ErrorCode.INVALID_OPERATION


def test_mutation_operations_skip_unchanged_fields():
    empty = build_mutation_operations(
        addr="0x123e",
        current_name="main",
        new_name="main",
        comment="same",
        current_comment="same",
        local_renames=[{"old": "v3", "new": "v3"}],
    )
    assert empty == []


def test_mutation_operations_empty_comment_clears():
    ops = build_mutation_operations(
        addr="0x123e",
        current_name="main",
        new_name="main",
        comment="",
        current_comment="stale",
        local_renames=[],
    )
    assert ops == [{"kind": "comment", "addr": "0x123e", "comment": ""}]

    ops = build_mutation_operations(
        addr="0x123e",
        current_name="main",
        new_name="entry_main",
        comment="Program entry",
        current_comment="",
        local_renames=[{"old": "a1", "new": "argc"}, {"name": "v3", "new": "status"}],
    )
    assert ops[0]["kind"] == "rename"
    assert ops[0]["func"] == [{"addr": "0x123e", "name": "entry_main"}]
    assert ops[0]["local"] == [
        {"func_addr": "0x123e", "old": "a1", "new": "argc"},
        {"func_addr": "0x123e", "old": "v3", "new": "status"},
    ]
    assert ops[1] == {"kind": "comment", "addr": "0x123e", "comment": "Program entry"}


def test_attach_review_views_adds_dialog_fields():
    review = attach_review_views(SAMPLE)
    assert "summary" in review
    assert "prompt" in review
    assert review["local_rows"][0]["name"] == "a1"
    assert review["name"] == "main"
