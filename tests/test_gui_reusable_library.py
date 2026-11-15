import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

import app


def _setup_server(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {
        "base": None, "target": None, "seed": None,
        "ranker_wordlist": None, "ranker_cracked": None, "ranker_rules": None,
        "ranker_source_csv": None, "ranker_source_rules": None, "ranker_analysis_csv": None,
        "concentrator_files": [],
    })
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {
        **app.STATE, "status": "idle", "run_dir": None, "outputs": [], "logs": [],
    })
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    monkeypatch.setattr(app, "SESSIONS", {
        "library-test-session": {
            "csrf": "library-test-csrf", "expires": time.time() + 600, "role": "admin",
        }
    })
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {
        "Cookie": "rulest_session=library-test-session",
        "X-CSRF-Token": "library-test-csrf",
    }
    return server, thread, base_url, headers, data_dir, uploads_dir


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def _request_json(url, headers, payload=None, raw=None, method=None):
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers = {**headers, "Content-Type": "application/json"}
    else:
        body = raw
        request_headers = {**headers, "Content-Type": "application/octet-stream"}
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_wordlist_upload_is_moved_into_persistent_library_without_duplicate_copy(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        status, result = _request_json(
            base + "/api/upload/base?filename=large%20dictionary.txt",
            headers, raw=b"alpha\nbeta\ngamma\n", method="POST",
        )
        assert status == 200 and result["ok"] is True
        assert result["library"] is True
        assert result["category"] == "wordlists"
        asset = data_dir / "library" / "wordlists" / result["asset_id"]
        assert asset.read_bytes() == b"alpha\nbeta\ngamma\n"
        assert list(uploads_dir.iterdir()) == []
        assert app.UPLOADS_META["base"]["path"] == asset
        assert app.UPLOADS_META["base"]["library"] is True
    finally:
        _stop_server(server, thread)


def test_rulestripper_upload_api_accepts_text_files_with_arbitrary_names_and_extensions(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        cases = (
            ("wordlist", b"password\nadmin\n"),
            ("hashmob.micro.found", b"alpha\nbeta\n"),
            ("dictionary.backup.2026", b"one\ntwo\n"),
        )
        uploaded_ids = []
        for filename, content in cases:
            status, result = _request_json(
                base + "/api/tools/upload/rulestripper_base?filename=" + urllib.parse.quote(filename),
                headers, raw=content, method="POST",
            )
            assert status == 200 and result["ok"] is True, result
            assert result["library"] is True
            asset = data_dir / "library" / "wordlists" / result["asset_id"]
            assert asset.read_bytes() == content
            uploaded_ids.append(result["asset_id"])

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert set(uploaded_ids).issubset({item["id"] for item in listed["wordlists"]})
        assert list(uploads_dir.iterdir()) == []
    finally:
        _stop_server(server, thread)


def test_saved_assets_can_be_listed_selected_and_survive_run_cleanup(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        rules_dir = data_dir / "library" / "rules"
        wordlist_dir.mkdir(parents=True)
        rules_dir.mkdir(parents=True)
        word_id = "a" * 32 + "_common_words.txt"
        rules_id = "b" * 32 + "_best_rules.rule"
        (wordlist_dir / word_id).write_bytes(b"password\nwelcome\n")
        (rules_dir / rules_id).write_bytes(b":\n$1\n")

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert [item["id"] for item in listed["wordlists"]] == [word_id]
        assert [item["id"] for item in listed["rules"]] == [rules_id]

        status, selected = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "target", "asset_id": word_id}, method="POST",
        )
        assert status == 200 and selected["ok"] is True
        assert app.UPLOADS_META["target"]["path"] == wordlist_dir / word_id
        assert app.UPLOADS_META["target"]["name"] == "common_words.txt"

        status, selected_rules = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "seed", "asset_id": rules_id}, method="POST",
        )
        assert status == 200 and selected_rules["category"] == "rules"
        assert app.UPLOADS_META["seed"]["path"] == rules_dir / rules_id

        # Selecting a persistent asset and ending a job must only clear the
        # active references; the on-disk reusable library remains untouched.
        app.cleanup_uploaded_files(log_message=False)
        assert app.UPLOADS_META["target"] is None
        assert (wordlist_dir / word_id).is_file()
        assert (rules_dir / rules_id).is_file()

        run_dir = data_dir / "run-to-delete"
        run_dir.mkdir()
        (run_dir / "output.rule").write_text(":\n", encoding="utf-8")
        result = app.clear_run_directories()
        assert result["deleted_directories"] == 1
        assert not run_dir.exists()
        assert (wordlist_dir / word_id).is_file()
        assert (rules_dir / rules_id).is_file()
        assert result["library_preserved"] is True
    finally:
        _stop_server(server, thread)


def test_library_listing_uses_python38_compatible_lstat_and_skips_symlinks(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    monkeypatch.setattr(app, "DATA", data_dir)
    wordlist_dir = data_dir / "library" / "wordlists"
    rules_dir = data_dir / "library" / "rules"
    wordlist_dir.mkdir(parents=True)
    rules_dir.mkdir(parents=True)

    saved_wordlist = wordlist_dir / "saved_words.txt"
    saved_wordlist.write_text("alpha\nbeta\n", encoding="utf-8")
    outside_target = tmp_path / "outside.rule"
    outside_target.write_text(":\n", encoding="utf-8")
    try:
        (rules_dir / "external.rule").symlink_to(outside_target)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available in this environment")

    listed = app.list_library_assets()
    assert [item["id"] for item in listed["wordlists"]] == ["saved_words.txt"]
    assert listed["wordlists"][0]["size"] == saved_wordlist.stat().st_size
    assert listed["rules"] == []


def test_library_selection_rejects_traversal_and_wrong_input_category(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        rules_id = "c" * 32 + "_only.rule"
        (rules_dir / rules_id).write_text(":\n", encoding="utf-8")

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "base", "asset_id": rules_id}, method="POST",
        )
        assert status == 404
        assert "no longer exists" in result["error"].lower() or "invalid" in result["error"].lower()
        assert app.UPLOADS_META["base"] is None

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "base", "asset_id": "../../etc/passwd"}, method="POST",
        )
        assert status == 404
        assert app.UPLOADS_META["base"] is None

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "ranker_analysis_csv", "asset_id": rules_id}, method="POST",
        )
        assert status == 400
    finally:
        _stop_server(server, thread)


def test_concentrator_can_select_multiple_saved_rule_files_and_deduplicates(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        ids = [f"{letter * 32}_rule_{letter}.rule" for letter in ("d", "e")]
        for asset_id in ids:
            (rules_dir / asset_id).write_text(":\n", encoding="utf-8")

        for asset_id in ids:
            status, result = _request_json(
                base + "/api/library/select", headers,
                payload={"field": "concentrator_files", "asset_id": asset_id}, method="POST",
            )
            assert status == 200 and result["ok"] is True
        assert len(app.UPLOADS_META["concentrator_files"]) == 2

        status, duplicate = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "concentrator_files", "asset_id": ids[0]}, method="POST",
        )
        assert status == 200 and duplicate["already_selected"] is True
        assert len(app.UPLOADS_META["concentrator_files"]) == 2
    finally:
        _stop_server(server, thread)


def test_rule_upload_routes_publish_assets_to_rules_dropdown(tmp_path, monkeypatch):
    """Every rule upload entry point must immediately populate the shared rules library."""
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    uploads = [
        ("/api/upload/seed?filename=seed_rules.rule", "seed rules"),
        ("/api/ranker/upload/ranker_rules?filename=candidate_rules.rule", "candidate rules"),
        ("/api/ranker/upload/ranker_source_rules?filename=source_rules.rule", "source rules"),
        ("/api/concentrator/upload/concentrator_files?filename=concentrator_rules.rule", "concentrator rules"),
    ]
    try:
        expected_ids = []
        for index, (endpoint, content) in enumerate(uploads):
            status, result = _request_json(base + endpoint, headers, raw=f":\n${index}\n".encode(), method="POST")
            assert status == 200 and result["ok"] is True
            assert result["library"] is True
            assert result["category"] == "rules"
            expected_ids.append(result["asset_id"])

        status, listed = _request_json(base + "/api/library?refresh=1", headers, method="GET")
        assert status == 200
        assert {item["id"] for item in listed["rules"]} == set(expected_ids)
        for asset_id in expected_ids:
            assert (data_dir / "library" / "rules" / asset_id).is_file()
    finally:
        _stop_server(server, thread)


def test_legacy_plain_named_rule_assets_are_visible_and_selectable(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "legacy_custom_rules.rule").write_text(":\n$1\n", encoding="utf-8")

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert any(item["id"] == "legacy_custom_rules.rule" and item["name"] == "legacy_custom_rules.rule" for item in listed["rules"])

        status, selected = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "seed", "asset_id": "legacy_custom_rules.rule"}, method="POST",
        )
        assert status == 200 and selected["ok"] is True
        assert app.UPLOADS_META["seed"]["path"] == rules_dir / "legacy_custom_rules.rule"
    finally:
        _stop_server(server, thread)


def test_ranker_fingerprint_cache_files_are_hidden_and_not_selectable(tmp_path, monkeypatch):
    """Derived .npy/.json hash caches must never appear as reusable inputs."""
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        source_id = "d" * 32 + "_large_dictionary.txt"
        source = wordlist_dir / source_id
        source.write_text("alpha\nbeta\n", encoding="utf-8")

        # These are created by rule_ranker.hashing.cache_paths() next to source.
        cache_npy = wordlist_dir / (source_id + ".fnv1a64.max256.npy")
        cache_json = wordlist_dir / (source_id + ".fnv1a64.max256.json")
        cache_npy.write_bytes(b"not a real numpy payload; listing must not open it")
        cache_json.write_text('{"algorithm":"fnv1a64"}', encoding="utf-8")

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert [item["id"] for item in listed["wordlists"]] == [source_id]

        # Hiding is enforced by the selection API too, not only by the dropdown.
        for cache_id in (cache_npy.name, cache_json.name):
            status, result = _request_json(
                base + "/api/library/select", headers,
                payload={"field": "target", "asset_id": cache_id}, method="POST",
            )
            assert status == 404
            assert "invalid" in result["error"].lower()

        # The source wordlist remains selectable as usual.
        status, selected = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "target", "asset_id": source_id}, method="POST",
        )
        assert status == 200 and selected["ok"] is True
        assert app.UPLOADS_META["target"]["path"] == source
    finally:
        _stop_server(server, thread)



def test_all_npy_and_json_assets_are_hidden_even_without_ranker_cache_name(tmp_path, monkeypatch):
    """Library menus must never offer .npy/.json artifacts, regardless of basename."""
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        source_id = "e" * 32 + "_plain_dictionary.txt"
        (wordlist_dir / source_id).write_text("alpha\nbeta\n", encoding="utf-8")

        # Exercise generic names too: cache files from older versions or custom
        # names may not carry the current .fnv1a64.maxNNN marker.
        hidden_ids = (
            "fingerprints.npy",
            "fingerprints.json",
            "dictionary-cache.npy",
            "dictionary-cache.json",
            "legacy_" + "f" * 32 + "_opaque.npy",
            "legacy_" + "a" * 32 + "_opaque.json",
        )
        for name in hidden_ids:
            path = wordlist_dir / name
            path.write_bytes(b"internal cache") if name.endswith(".npy") else path.write_text("{}", encoding="utf-8")

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert [item["id"] for item in listed["wordlists"]] == [source_id]

        for asset_id in hidden_ids:
            status, result = _request_json(
                base + "/api/library/select", headers,
                payload={"field": "target", "asset_id": asset_id}, method="POST",
            )
            assert status == 404
            assert "invalid" in result["error"].lower()
    finally:
        _stop_server(server, thread)


def test_library_listing_collapses_identical_legacy_assets_but_keeps_distinct_variants(tmp_path, monkeypatch):
    """Old repeated uploads collapse by content, not by filename/size alone."""
    data_dir = tmp_path / "runs"
    monkeypatch.setattr(app, "DATA", data_dir)
    wordlist_dir = data_dir / "library" / "wordlists"
    wordlist_dir.mkdir(parents=True)

    duplicate_a = "1" * 32 + "_shared.txt"
    duplicate_b = "2" * 32 + "_shared.txt"
    different = "3" * 32 + "_shared.txt"
    payload = b"alpha\nbravo\n"
    (wordlist_dir / duplicate_a).write_bytes(payload)
    (wordlist_dir / duplicate_b).write_bytes(payload)
    # Same visible name and size, but different content must remain selectable.
    (wordlist_dir / different).write_bytes(b"gamma\ndelta\n")

    listed = app.list_library_assets()
    items = listed["wordlists"]
    assert len(items) == 2
    assert {item["id"] for item in items} == {duplicate_a, different}
    assert all("label" in item for item in items)

    # The digest index makes subsequent refreshes metadata-only for unchanged files.
    digest_index = data_dir / "library" / ".asset_hashes.sqlite3"
    assert digest_index.is_file()
    listed_again = app.list_library_assets()
    assert [item["id"] for item in listed_again["wordlists"]] == [item["id"] for item in items]


def test_reuploading_same_library_file_reuses_existing_asset_id(tmp_path, monkeypatch):
    """Uploading the same file in separate input slots must not add menu duplicates."""
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        content = b"alpha\nbeta\ngamma\n"
        status, first = _request_json(
            base + "/api/upload/base?filename=shared_dictionary.txt",
            headers, raw=content, method="POST",
        )
        assert status == 200 and first["ok"] is True

        status, second = _request_json(
            base + "/api/upload/target?filename=shared_dictionary.txt",
            headers, raw=content, method="POST",
        )
        assert status == 200 and second["ok"] is True
        assert second["asset_id"] == first["asset_id"]
        assert list((data_dir / "library" / "wordlists").iterdir()) == [
            data_dir / "library" / "wordlists" / first["asset_id"]
        ]
        assert list(uploads_dir.iterdir()) == []

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert [item["id"] for item in listed["wordlists"]] == [first["asset_id"]]
    finally:
        _stop_server(server, thread)


def test_reuploading_same_name_and_size_with_different_content_keeps_both_assets(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        first_content = b"alpha\nbravo\n"
        second_content = b"gamma\ndelta\n"
        assert len(first_content) == len(second_content)
        status, first = _request_json(
            base + "/api/upload/base?filename=same_name.txt",
            headers, raw=first_content, method="POST",
        )
        assert status == 200
        status, second = _request_json(
            base + "/api/upload/target?filename=same_name.txt",
            headers, raw=second_content, method="POST",
        )
        assert status == 200
        assert first["asset_id"] != second["asset_id"]
        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        options = listed["wordlists"]
        assert {item["id"] for item in options} == {first["asset_id"], second["asset_id"]}
        assert all("label" in item and "variant" in item["label"] for item in options)
    finally:
        _stop_server(server, thread)


def test_library_filename_search_returns_full_path_and_matches_filename_only(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        rules_dir = data_dir / "library" / "rules"
        wordlist_dir.mkdir(parents=True)
        rules_dir.mkdir(parents=True)
        word_id = "a" * 32 + "_RockYou-2026.txt"
        rules_id = "b" * 32 + "_rockyou-derived.rule"
        (wordlist_dir / word_id).write_bytes(b"alpha\n")
        (rules_dir / rules_id).write_bytes(b"$1\n")

        status, result = _request_json(
            base + "/api/library/search?q=ROCKYOU", headers, method="GET",
        )
        assert status == 200 and result["total"] == 2
        assert {item["name"] for item in result["results"]} == {"RockYou-2026.txt", "rockyou-derived.rule"}
        assert all(item["path"].startswith(str(data_dir / "library")) for item in result["results"])

        # The search expression is filename-only, not a search through folder paths.
        status, result = _request_json(
            base + "/api/library/search?q=wordlists", headers, method="GET",
        )
        assert status == 200 and result["total"] == 0
    finally:
        _stop_server(server, thread)


def test_filename_search_includes_nested_work_folder_files_and_work_file_download(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        run_dir = data_dir / "run-a1b2c3d4e5"
        nested = run_dir / "results" / "final"
        nested.mkdir(parents=True)
        result_file = nested / "optimized_rules.rule"
        payload = b":\n$1\n$2\n"
        result_file.write_bytes(payload)

        status, result = _request_json(
            base + "/api/library/search?q=OPTIMIZED_RULES", headers, method="GET",
        )
        assert status == 200 and result["total"] == 1
        match = result["results"][0]
        assert match["source"] == "run"
        assert match["run_id"] == run_dir.name
        assert match["relative_path"] == "results/final/optimized_rules.rule"
        assert match["path"] == str(result_file)

        # The search expression is basename-only, not a match on folder names.
        status, result = _request_json(
            base + "/api/library/search?q=results", headers, method="GET",
        )
        assert status == 200 and result["total"] == 0

        query = urllib.parse.urlencode({
            "run_id": match["run_id"], "relative_path": match["relative_path"],
        })
        request = urllib.request.Request(
            base + "/api/run-storage/file-download?" + query,
            headers=headers, method="GET",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert response.read() == payload

        bad_query = urllib.parse.urlencode({
            "run_id": match["run_id"], "relative_path": "../outside.txt",
        })
        bad_request = urllib.request.Request(
            base + "/api/run-storage/file-download?" + bad_query,
            headers=headers, method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(bad_request, timeout=5)
        assert error.value.code == 404
    finally:
        _stop_server(server, thread)


def test_run_outputs_zip_download_contains_all_outputs_only_when_more_than_three(tmp_path, monkeypatch):
    import io
    import zipfile

    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        run_dir = data_dir / "zip-run-123"
        run_dir.mkdir()
        outputs = []
        expected = {}
        for index in range(4):
            name = f"result-{index + 1}.rule"
            payload = f"rule-{index + 1}\n".encode("ascii")
            (run_dir / name).write_bytes(payload)
            outputs.append({"name": name, "size": len(payload)})
            expected[name] = payload
        app.STATE.update({
            "status": "completed", "tool": "ranker", "run_dir": str(run_dir), "outputs": outputs,
        })

        request = urllib.request.Request(
            base + "/api/run-storage/download-outputs.zip", headers=headers, method="GET",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert response.headers.get_content_type() == "application/zip"
            archive_bytes = response.read()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            assert set(archive.namelist()) == set(expected)
            assert {name: archive.read(name) for name in archive.namelist()} == expected

        # Three files do not expose the bulk archive action at the API level.
        app.STATE["outputs"] = outputs[:3]
        too_few = urllib.request.Request(
            base + "/api/run-storage/download-outputs.zip", headers=headers, method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(too_few, timeout=5)
        assert error.value.code == 409
    finally:
        _stop_server(server, thread)


def test_library_search_result_download_endpoint_streams_saved_file(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        asset_id = "c" * 32 + "_download-me.rule"
        content = b":\n$1\n$2\n"
        (rules_dir / asset_id).write_bytes(content)
        query = urllib.parse.urlencode({"category": "rules", "asset_id": asset_id})
        request = urllib.request.Request(base + "/api/library/download?" + query, headers=headers, method="GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            downloaded = response.read()
            assert response.status == 200
            assert response.headers.get_content_type() == "application/octet-stream"
            assert "download-me.rule" in response.headers.get("Content-Disposition", "")
        assert downloaded == content

        bad_query = urllib.parse.urlencode({"category": "../outside", "asset_id": asset_id})
        bad_request = urllib.request.Request(base + "/api/library/download?" + bad_query, headers=headers, method="GET")
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(bad_request, timeout=5)
        assert error.value.code == 404
    finally:
        _stop_server(server, thread)


def test_library_duplicate_scan_matches_same_name_and_identical_content_separately(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        same_name_a = "a" * 32 + "_common.txt"
        same_name_b = "b" * 32 + "_common.txt"
        identical_other_name = "c" * 32 + "_renamed.txt"
        (wordlist_dir / same_name_a).write_bytes(b"alpha\nbeta\n")
        (wordlist_dir / same_name_b).write_bytes(b"different content\n")
        (wordlist_dir / identical_other_name).write_bytes(b"alpha\nbeta\n")

        status, result = _request_json(
            base + "/api/library/scan-duplicates", headers, payload={}, method="POST",
        )
        assert status == 200 and result["duplicate_group_count"] == 1
        group = result["duplicate_groups"][0]
        assert set(group["reasons"]) == {"same filename", "identical content"}
        files = {item["id"]: item for item in group["files"]}
        assert set(files) == {same_name_a, same_name_b, identical_other_name}
        assert files[same_name_b]["suggest_delete"] is False
        assert sum(bool(item["suggest_delete"]) for item in files.values()) == 1
        assert all(item["path"].startswith(str(wordlist_dir)) for item in files.values())
    finally:
        _stop_server(server, thread)


def test_library_delete_selected_removes_only_checked_file_and_preserves_checksum_copy(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        duplicate_a = "a" * 32 + "_same.txt"
        duplicate_b = "b" * 32 + "_renamed.txt"
        different_same_name = "c" * 32 + "_same.txt"
        (wordlist_dir / duplicate_a).write_bytes(b"identical\n")
        (wordlist_dir / duplicate_b).write_bytes(b"identical\n")
        (wordlist_dir / different_same_name).write_bytes(b"not identical\n")
        status, scan = _request_json(base + "/api/library/scan-duplicates", headers, payload={}, method="POST")
        assert status == 200
        group = scan["duplicate_groups"][0]
        suggested = next(item for item in group["files"] if item["suggest_delete"])
        status, deleted = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [{"category": "wordlists", "asset_id": suggested["id"]}]}, method="POST",
        )
        assert status == 200 and deleted["deleted_count"] == 1
        assert not (wordlist_dir / suggested["id"]).exists()
        assert (wordlist_dir / (duplicate_a if suggested["id"] != duplicate_a else duplicate_b)).exists()
        assert (wordlist_dir / different_same_name).exists()
    finally:
        _stop_server(server, thread)


def test_library_delete_rejects_removing_all_checksum_copies_and_active_inputs(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        asset_a = "d" * 32 + "_one.txt"
        asset_b = "e" * 32 + "_two.txt"
        (wordlist_dir / asset_a).write_bytes(b"same bytes")
        (wordlist_dir / asset_b).write_bytes(b"same bytes")

        status, result = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [
                {"category": "wordlists", "asset_id": asset_a},
                {"category": "wordlists", "asset_id": asset_b},
            ]}, method="POST",
        )
        assert status == 400
        assert "at least one" in result["error"].lower()
        assert (wordlist_dir / asset_a).is_file() and (wordlist_dir / asset_b).is_file()

        app.UPLOADS_META["base"] = {
            "library": True, "category": "wordlists", "asset_id": asset_b,
            "path": wordlist_dir / asset_b,
        }
        status, result = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [{"category": "wordlists", "asset_id": asset_b}]}, method="POST",
        )
        assert status == 409
        assert "mounted" in result["error"].lower()
        assert (wordlist_dir / asset_b).is_file()
    finally:
        _stop_server(server, thread)


def test_library_allows_manual_deletion_of_same_name_different_content_variant(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        wordlist_dir.mkdir(parents=True)
        keep_id = "f" * 32 + "_shared-name.txt"
        remove_id = "0" * 32 + "_shared-name.txt"
        (wordlist_dir / keep_id).write_bytes(b"first content")
        (wordlist_dir / remove_id).write_bytes(b"second content")

        status, scan = _request_json(base + "/api/library/scan-duplicates", headers, payload={}, method="POST")
        assert status == 200 and scan["duplicate_group_count"] == 1
        target = next(item for item in scan["duplicate_groups"][0]["files"] if item["id"] == remove_id)
        assert target["suggest_delete"] is False

        status, result = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [{"category": "wordlists", "asset_id": remove_id}]}, method="POST",
        )
        assert status == 200 and result["deleted_count"] == 1
        assert not (wordlist_dir / remove_id).exists()
        assert (wordlist_dir / keep_id).is_file()
    finally:
        _stop_server(server, thread)



def test_library_duplicate_scan_includes_same_name_files_from_completed_work_folders(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        first = data_dir / "run-one" / "nested"
        second = data_dir / "run-two" / "nested"
        library = data_dir / "library" / "rules"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        library.mkdir(parents=True)
        (first / "shared.rule").write_bytes(b"first work output")
        (second / "shared.rule").write_bytes(b"second work output")
        (library / ("a" * 32 + "_shared.rule")).write_bytes(b"library copy")

        status, result = _request_json(
            base + "/api/library/scan-duplicates", headers, payload={}, method="POST",
        )
        assert status == 200
        assert result["scanned_work_files"] == 2
        group = next(group for group in result["duplicate_groups"] if group["files"][0]["name"] == "shared.rule")
        assert "same filename" in group["reasons"]
        assert len(group["files"]) == 3
        assert {item["source"] for item in group["files"]} == {"library", "run"}
        assert {item["path"] for item in group["files"]} == {
            str(first / "shared.rule"), str(second / "shared.rule"),
            str(library / ("a" * 32 + "_shared.rule")),
        }
        assert all(item["suggest_delete"] is False for item in group["files"])
    finally:
        _stop_server(server, thread)


def test_duplicate_cleanup_can_remove_selected_work_file_but_protect_current_run(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        current_dir = data_dir / "current-run"
        old_dir = data_dir / "old-run"
        current_dir.mkdir()
        old_dir.mkdir()
        current_file = current_dir / "result.rule"
        old_file = old_dir / "result.rule"
        current_file.write_bytes(b"current output")
        old_file.write_bytes(b"older output")
        app.STATE["run_dir"] = current_dir

        status, scan = _request_json(
            base + "/api/library/scan-duplicates", headers, payload={}, method="POST",
        )
        assert status == 200
        group = next(group for group in scan["duplicate_groups"] if group["files"][0]["name"] == "result.rule")
        files = {item["run_id"]: item for item in group["files"]}
        assert files["current-run"]["deletable"] is False
        assert files["old-run"]["deletable"] is True

        status, deleted = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [{
                "source": "run", "run_id": "old-run", "relative_path": "result.rule",
            }]}, method="POST",
        )
        assert status == 200 and deleted["deleted_count"] == 1
        assert not old_file.exists()
        assert current_file.is_file()
    finally:
        _stop_server(server, thread)


def test_duplicate_cleanup_rejects_deleting_every_same_name_work_file(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        paths = []
        for folder_name, contents in (("run-a", b"one"), ("run-b", b"two")):
            folder = data_dir / folder_name
            folder.mkdir()
            file_path = folder / "duplicate.log"
            file_path.write_bytes(contents)
            paths.append(file_path)
        status, result = _request_json(
            base + "/api/library/delete-selected", headers,
            payload={"items": [
                {"source": "run", "run_id": "run-a", "relative_path": "duplicate.log"},
                {"source": "run", "run_id": "run-b", "relative_path": "duplicate.log"},
            ]}, method="POST",
        )
        assert status == 400
        assert "duplicated filename" in result["error"].lower()
        assert all(path.is_file() for path in paths)
    finally:
        _stop_server(server, thread)
