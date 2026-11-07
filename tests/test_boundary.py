"""Unit tests for zerotruss/boundary.py."""
import json
from datetime import datetime
from pathlib import Path

import pytest

from zerotruss.boundary import (
    check, load_boundary, load_boundary_file, load_signed_boundary_file, path_arguments, split_absolute, summary)
from zerotruss.signing import new_private_key, public_key_pem, sign


# ----- split_absolute -----

def test_splits_an_absolute_path_into_parts():
    assert split_absolute("/data/test_dir/file1.txt") == ["data", "test_dir", "file1.txt"]
    assert split_absolute("/data") == ["data"]


def test_the_root_has_no_parts():
    # An empty list, which is not the same as None: the root is a valid absolute path.
    assert split_absolute("/") == []
    assert split_absolute("/") is not None


def test_dots_and_double_slashes_are_tidied():
    assert split_absolute("/data//test_dir/./a") == ["data", "test_dir", "a"]
    assert split_absolute("/data/test_dir/") == ["data", "test_dir"]


def test_dotdot_removes_the_part_before_it():
    assert split_absolute("/data/test_dir/../secret") == ["data", "secret"]
    assert split_absolute("/data/test_dir/a/../b") == ["data", "test_dir", "b"]
    assert split_absolute("/data/test_dir/a/../../..") == []


def test_dotdot_at_the_root_stays_at_the_root():
    assert split_absolute("/../etc") == ["etc"]
    assert split_absolute("/..") == []


def test_empty_and_relative_paths_give_nothing():
    for path in ["", "file1.txt", "./file1.txt", "../file1.txt", "~/file1.txt"]:
        assert split_absolute(path) is None


def test_names_are_kept_exactly_as_written():
    # No case folding: "TEST_DIR" and "test_dir" are different names here.
    assert split_absolute("/data/TEST_DIR") == ["data", "TEST_DIR"]


# ----- path_arguments -----

def test_finds_a_single_path():
    assert path_arguments({"path": "/a"}) == [("path", "/a")]


def test_finds_every_path_in_a_list():
    assert path_arguments({"paths": ["/a", "/b"]}) == [("paths", "/a"), ("paths", "/b")]


def test_finds_source_and_destination():
    found = path_arguments({"destination": "/b", "source": "/a"})
    assert found == [("source", "/a"), ("destination", "/b")]


def test_no_path_arguments_means_nothing_to_check():
    assert path_arguments(None) == []
    assert path_arguments({}) == []
    assert path_arguments({"paths": []}) == []


def test_other_arguments_are_not_treated_as_paths():
    found = path_arguments({"path": "/a", "head": 5, "note": "/etc/passwd"})
    assert found == [("path", "/a")]


def test_unreadable_shapes_are_errors():
    bad = [
        {"path": 5},
        {"path": None},
        {"path": True},
        {"path": {"a": 1}},
        {"paths": ["/a", 7]},
        {"paths": [["/a"]]},
        {"paths": [None]},
    ]
    for arguments in bad:
        with pytest.raises(ValueError, match="not in a readable shape"):
            path_arguments(arguments)


def test_the_error_names_the_argument_but_not_the_path():
    with pytest.raises(ValueError) as error:
        path_arguments({"paths": ["/secret-name", 7]})
    assert "paths" in str(error.value) and "secret-name" not in str(error.value)
    with pytest.raises(ValueError, match="destination"):
        path_arguments({"destination": 5})


def test_arguments_that_are_not_an_object_are_errors():
    for arguments in ["a string", ["/etc"], 7, True]:
        with pytest.raises(ValueError, match="not an object"):
            path_arguments(arguments)


# ----- load_boundary -----

def at(text):
    return datetime.fromisoformat(text)


def file_text(folders, expires_at, tools=("read_text_file", "list_directory")):
    return json.dumps({"allowed_tools": list(tools), "allowed_folders": folders, "expires_at": expires_at})


def test_reads_the_three_fields():
    boundary = load_boundary(file_text(["/data/test_dir", "/data/other"], "2030-01-01T00:00:00Z"))
    assert boundary["allowed_tools"] == ["read_text_file", "list_directory"]
    assert boundary["allowed_folders"] == [["data", "test_dir"], ["data", "other"]]
    assert boundary["expires_at"] == at("2030-01-01T00:00:00+00:00")


def test_folders_are_tidied_like_paths():
    boundary = load_boundary(file_text(["/data//test_dir/../test_dir/"], "2030-01-01T00:00:00Z"))
    assert boundary["allowed_folders"] == [["data", "test_dir"]]


def test_a_date_with_an_offset_is_converted_to_utc():
    boundary = load_boundary(file_text([], "2030-01-01T05:30:00+05:30"))
    assert boundary["expires_at"] == at("2030-01-01T00:00:00+00:00")


def test_empty_lists_are_accepted():
    # Nothing allowed: every call will be denied. Safe, so it is not an error.
    load_boundary('{"allowed_tools": [], "allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z"}')


def test_unknown_field_is_rejected():
    text = '{"allowed_tools": [], "allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z", "allowed_tool": ["x"]}'
    with pytest.raises(ValueError, match="unknown field"):
        load_boundary(text)


def test_missing_field_is_rejected():
    no_tools = '{"allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z"}'
    no_folders = '{"allowed_tools": [], "expires_at": "2030-01-01T00:00:00Z"}'
    no_expiry = '{"allowed_tools": [], "allowed_folders": []}'
    for text in [no_tools, no_folders, no_expiry]:
        with pytest.raises(ValueError, match="missing field"):
            load_boundary(text)


def test_wrong_types_are_rejected():
    expires = '"expires_at": "2030-01-01T00:00:00Z"'
    bad = [
        '{"allowed_tools": "read_text_file", "allowed_folders": [], ' + expires + '}',
        '{"allowed_tools": [], "allowed_folders": [5], ' + expires + '}',
        '{"allowed_tools": [true], "allowed_folders": [], ' + expires + '}',
        '{"allowed_tools": [], "allowed_folders": [], "expires_at": 2030}',
        '{"allowed_tools": [], "allowed_folders": [], "expires_at": null}',
    ]
    for text in bad:
        with pytest.raises(ValueError):
            load_boundary(text)


def test_relative_or_empty_folders_are_rejected():
    for folder in ["test_dir", "./test_dir", "../test_dir", "~/test_dir", ""]:
        with pytest.raises(ValueError, match="absolute"):
            load_boundary(file_text([folder], "2030-01-01T00:00:00Z"))


def test_bad_dates_are_rejected():
    for date in ["tomorrow", "2030-01-01", "2030-01-01T00:00:00", "2030-13-01T00:00:00Z", "", "2030-01-01 00:00:00Z"]:
        with pytest.raises(ValueError, match="expires_at"):
            load_boundary(file_text([], date))


def test_text_that_is_not_json_is_rejected():
    for text in ["", "not json", "[]", "5", "null"]:
        with pytest.raises(ValueError, match="not valid"):
            load_boundary(text)


def test_not_a_number_values_are_rejected():
    text = '{"allowed_tools": [], "allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z", "x": NaN}'
    with pytest.raises(ValueError, match="NaN"):
        load_boundary(text)


def test_load_reports_a_missing_file(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        load_boundary_file(tmp_path / "no_such_boundary_file.json")


def test_load_reads_a_file(tmp_path):
    path = tmp_path / "boundary.json"
    path.write_text(file_text(["/data/test_dir"], "2030-01-01T00:00:00Z"))
    assert load_boundary_file(path)["allowed_folders"] == [["data", "test_dir"]]


def test_the_summary_counts_tools_and_folders_and_shows_the_expiry():
    boundary = load_boundary(file_text(["/data/a", "/data/b"], "2030-01-01T00:00:00Z"))
    assert summary(boundary) == "tools: 2, folders: 2, expires: 2030-01-01T00:00:00Z"


def test_the_example_boundary_file_loads():
    boundary = load_boundary_file(Path(__file__).parent.parent / "boundary.example.json")
    assert "read_text_file" in boundary["allowed_tools"] and len(boundary["allowed_folders"]) == 1


def test_the_real_boundary_file_loads_if_present():
    path = Path(__file__).parent.parent / "boundary.json"
    if path.exists():
        load_boundary_file(path)


# ----- check -----

TODAY = at("2026-11-06T00:00:00+00:00")


def make_boundary():
    return load_boundary(json.dumps({
        "allowed_tools": ["read_text_file", "read_multiple_files", "move_file", "list_allowed_directories"],
        "allowed_folders": ["/data/test_dir"],
        "expires_at": "2030-01-01T00:00:00Z",
    }))


def run_check(tool, arguments):
    """Check a call on a fixed "today", which is before the boundary expires."""
    return check(make_boundary(), tool, arguments, TODAY)


def assert_allowed(tool, arguments):
    assert run_check(tool, arguments) is None, f"{tool} {arguments}"


def assert_denied(tool, arguments, reason_contains):
    reason = run_check(tool, arguments)
    assert reason is not None and reason_contains in reason, f"{tool} {arguments}: reason was {reason}"


def test_a_listed_tool_with_a_path_inside_is_allowed():
    assert_allowed("read_text_file", {"path": "/data/test_dir/file1.txt"})
    assert_allowed("read_text_file", {"path": "/data/test_dir/a/b/c.txt"})


def test_the_folder_itself_is_allowed():
    assert_allowed("read_text_file", {"path": "/data/test_dir"})
    assert_allowed("read_text_file", {"path": "/data/test_dir/"})


def test_a_path_outside_the_folder_is_denied():
    assert_denied("read_text_file", {"path": "/data/other/file.txt"}, "path is outside")
    assert_denied("read_text_file", {"path": "/etc/passwd"}, "path is outside")
    assert_denied("read_text_file", {"path": "/data"}, "path is outside")
    assert_denied("read_text_file", {"path": "/"}, "path is outside")


def test_dotdot_that_escapes_is_denied():
    assert_denied("read_text_file", {"path": "/data/test_dir/../secret.txt"}, "outside")
    assert_denied("read_text_file", {"path": "/data/test_dir/a/../../.."}, "outside")


def test_dotdot_that_stays_inside_is_allowed():
    assert_allowed("read_text_file", {"path": "/data/test_dir/a/../b.txt"})
    assert_allowed("read_text_file", {"path": "/data//test_dir/./file1.txt"})


def test_dotdot_above_the_root_stays_at_the_root():
    # "/.." is "/" on a real system, so this really is /data/test_dir/file1.txt.
    assert_allowed("read_text_file", {"path": "/../data/test_dir/file1.txt"})
    assert_denied("read_text_file", {"path": "/../etc/passwd"}, "outside")


def test_a_folder_name_prefix_is_not_a_match():
    assert_denied("read_text_file", {"path": "/data/test_dir_evil/file.txt"}, "outside")
    assert_denied("read_text_file", {"path": "/data/test_dir2"}, "outside")


def test_a_different_letter_case_is_denied():
    # macOS is case-insensitive, so this may be a real match, but denying is the safe side.
    assert_denied("read_text_file", {"path": "/data/TEST_DIR/file1.txt"}, "outside")


def test_empty_and_relative_paths_are_denied():
    for path in ["", "file1.txt", "./file1.txt", "../file1.txt", "~/file1.txt"]:
        assert_denied("read_text_file", {"path": path}, "not an absolute path")


def test_every_path_in_a_list_is_checked():
    assert_allowed("read_multiple_files", {"paths": ["/data/test_dir/a", "/data/test_dir/b"]})
    assert_denied("read_multiple_files", {"paths": ["/data/test_dir/a", "/etc/passwd"]}, "paths is outside")


def test_source_and_destination_are_both_checked():
    inside = "/data/test_dir/a"
    assert_allowed("move_file", {"source": inside, "destination": "/data/test_dir/b"})
    assert_denied("move_file", {"source": inside, "destination": "/tmp/b"}, "destination is outside")
    assert_denied("move_file", {"source": "/tmp/a", "destination": inside}, "source is outside")


def test_unreadable_arguments_are_denied():
    assert_denied("read_text_file", {"path": 5}, "not in a readable shape")
    assert_denied("read_text_file", {"path": None}, "not in a readable shape")
    assert_denied("read_text_file", {"path": True}, "not in a readable shape")
    assert_denied("read_multiple_files", {"paths": ["/data/test_dir/a", 7]}, "not in a readable shape")
    assert_denied("list_allowed_directories", "a string", "not an object")


def test_a_call_with_no_path_argument_is_allowed():
    assert_allowed("list_allowed_directories", {})
    assert_allowed("list_allowed_directories", None)


def test_other_arguments_are_not_checked_as_paths():
    assert_allowed("read_text_file", {"path": "/data/test_dir/a", "head": 5, "note": "/etc/passwd"})


def test_a_tool_not_on_the_list_is_denied():
    assert_denied("write_file", {"path": "/data/test_dir/a", "content": "x"}, "tool not allowed: write_file")
    assert_denied("", {}, "tool not allowed")
    assert_denied("READ_TEXT_FILE", {"path": "/data/test_dir/a"}, "tool not allowed")
    assert_denied("read_text_file ", {"path": "/data/test_dir/a"}, "tool not allowed")


def test_an_unlisted_tool_is_denied_even_with_a_good_path():
    assert_denied("create_directory", {"path": "/data/test_dir/new"}, "tool not allowed")


def test_a_path_in_any_allowed_folder_is_allowed():
    boundary = load_boundary(file_text(["/data/a", "/data/b"], "2030-01-01T00:00:00Z"))
    for path, allowed in [("/data/a/x", True), ("/data/b/x", True), ("/data/c/x", False), ("/data", False)]:
        reason = check(boundary, "read_text_file", {"path": path}, TODAY)
        assert (reason is None) == allowed, path


def test_no_allowed_folders_denies_every_path():
    boundary = load_boundary(file_text([], "2030-01-01T00:00:00Z"))
    reason = check(boundary, "read_text_file", {"path": "/data/test_dir/a"}, TODAY)
    assert "outside" in reason


def test_the_root_as_an_allowed_folder_allows_every_path():
    # Not a bug: it is what "/" means. It is the user's choice to put it in the file.
    boundary = load_boundary(file_text(["/"], "2030-01-01T00:00:00Z"))
    assert check(boundary, "read_text_file", {"path": "/etc/passwd"}, TODAY) is None


def test_the_boundary_expires_at_the_exact_moment():
    boundary = make_boundary()
    arguments = {"path": "/data/test_dir/a"}
    assert check(boundary, "read_text_file", arguments, at("2029-12-31T23:59:59+00:00")) is None
    for moment in ["2030-01-01T00:00:00+00:00", "2030-01-01T00:00:01+00:00", "2040-01-01T00:00:00+00:00"]:
        assert "expired" in check(boundary, "read_text_file", arguments, at(moment)), moment


def test_expiry_is_reported_before_anything_else():
    reason = check(make_boundary(), "write_file", {"path": "/etc/passwd"}, at("2031-01-01T00:00:00+00:00"))
    assert reason == "boundary expired"


def test_deny_reasons_never_contain_the_path():
    secret = "very-secret-name"
    calls = [
        ("read_text_file", {"path": f"/etc/{secret}"}),
        ("read_text_file", {"path": f"relative/{secret}"}),
        ("read_multiple_files", {"paths": [f"/etc/{secret}"]}),
        ("move_file", {"source": "/data/test_dir/a", "destination": f"/tmp/{secret}"}),
        ("write_file", {"path": f"/etc/{secret}"}),
    ]
    for tool, arguments in calls:
        reason = run_check(tool, arguments)
        assert reason is not None and secret not in reason, reason


# ----- load_signed_boundary_file -----

GOOD = file_text(["/data/test_dir"], "2030-01-01T00:00:00Z").encode()


# Write boundary.json, boundary.json.sig and boundary.pub into a folder; returns the three paths
def write_signed(folder, content=GOOD, private=None):
    private = private or new_private_key()
    boundary = folder / "boundary.json"
    boundary.write_bytes(content)
    signature = folder / "boundary.json.sig"
    signature.write_text(sign(private, content) + "\n")
    public = folder / "boundary.pub"
    public.write_bytes(public_key_pem(private))
    return boundary, signature, public


def test_a_correctly_signed_boundary_loads(tmp_path):
    boundary = load_signed_boundary_file(*write_signed(tmp_path))
    assert boundary == load_boundary(GOOD.decode())


def test_a_missing_file_stops_the_load(tmp_path):
    for index, what in enumerate(["boundary file", "signature file", "public key file"]):
        folder = tmp_path / str(index)
        folder.mkdir()
        paths = write_signed(folder)
        paths[index].unlink()
        with pytest.raises(ValueError, match=f"cannot read the {what}"):
            load_signed_boundary_file(*paths)


def test_a_boundary_changed_after_signing_is_refused(tmp_path):
    boundary, signature, public = write_signed(tmp_path)
    boundary.write_bytes(GOOD.replace(b"read_text_file", b"write_file"))
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file(boundary, signature, public)


def test_a_longer_expiry_written_after_signing_is_refused(tmp_path):
    boundary, signature, public = write_signed(tmp_path)
    boundary.write_bytes(GOOD.replace(b"2030-01-01", b"2099-01-01"))
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file(boundary, signature, public)


def test_a_signature_from_another_key_is_refused(tmp_path):
    boundary, signature, public = write_signed(tmp_path)
    public.write_bytes(public_key_pem(new_private_key()))
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file(boundary, signature, public)


def test_the_signature_of_a_different_boundary_is_refused(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    private = new_private_key()
    write_signed(first, GOOD, private)
    boundary, _, public = write_signed(second, GOOD.replace(b"/data/test_dir", b"/etc"), private)
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file(boundary, first / "boundary.json.sig", public)


def test_an_unsigned_file_is_never_parsed(tmp_path):
    boundary, signature, public = write_signed(tmp_path)
    boundary.write_bytes(b"this is not even json")
    with pytest.raises(ValueError) as error:
        load_signed_boundary_file(boundary, signature, public)
    assert "does not match" in str(error.value) and "not valid" not in str(error.value)


def test_a_signed_file_with_bad_content_is_still_refused(tmp_path):
    bad = b'{"allowed_tools": [], "allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z", "extra": 1}'
    with pytest.raises(ValueError, match="unknown field"):
        load_signed_boundary_file(*write_signed(tmp_path, bad))


def test_signed_bytes_that_are_not_text_are_refused(tmp_path):
    with pytest.raises(ValueError, match="not UTF-8"):
        load_signed_boundary_file(*write_signed(tmp_path, b"\xff\xfe\x00"))


def test_an_empty_or_garbage_signature_or_key_file_is_refused(tmp_path):
    for index, (name, content) in enumerate([("signature", ""), ("signature", "@@@@"), ("key", ""), ("key", "garbage")]):
        folder = tmp_path / str(index)
        folder.mkdir()
        boundary, signature, public = write_signed(folder)
        (signature if name == "signature" else public).write_text(content)
        with pytest.raises(ValueError):
            load_signed_boundary_file(boundary, signature, public)


def test_the_expiry_still_applies_to_a_signed_boundary(tmp_path):
    expired = file_text(["/data/test_dir"], "2000-01-01T00:00:00Z").encode()
    boundary = load_signed_boundary_file(*write_signed(tmp_path, expired))
    assert check(boundary, "read_text_file", {"path": "/data/test_dir/a"}, TODAY) == "boundary expired"
