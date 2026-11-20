import json

from rulest.pcfg_profile import compare_profiles, main, profile_wordlist, run_profile


def test_profile_counts_repeated_plain_lines_without_deduplication(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("abc123\nabc123\nOnlylower\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input"]["profiled_entries"] == 3
    assert profile["input"]["weighted_observations"] == 3
    assert profile["composition"]["weighted_class_combinations"]["lowercase+digits"] == 2
    assert profile["privacy"]["duplicate_lines_deduplicated"] is False
    assert "abc123" not in json.dumps(profile)


def test_profile_weights_frequency_formatted_lines(tmp_path):
    target = tmp_path / "frequency.txt"
    target.write_text("7\talpha123\n3 beta!\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input"]["profiled_entries"] == 2
    assert profile["input"]["weighted_observations"] == 10
    assert profile["composition"]["weighted_class_combinations"]["lowercase+digits"] == 7
    assert profile["composition"]["weighted_class_combinations"]["lowercase+symbols"] == 3


def test_profile_reports_length_and_skipped_line_metrics(tmp_path):
    target = tmp_path / "mixed.txt"
    target.write_text("\na\n12345678\n" + ("x" * 65) + "\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input"]["lines_seen"] == 4
    assert profile["input"]["empty_lines"] == 1
    assert profile["input"]["out_of_range_entries"] == 2
    assert profile["length"]["minimum"] == 8
    assert profile["length"]["maximum"] == 8
    assert profile["length"]["weighted_histogram"]["8-11"] == 1


def test_profile_handles_unicode_without_emitting_input_values(tmp_path):
    target = tmp_path / "unicode.txt"
    target.write_text("żółć123!\n", encoding="utf-8")

    profile = profile_wordlist(target, encoding="utf-8")

    assert profile["composition"]["weighted_class_presence"]["non_ascii"] == 1
    assert profile["composition"]["weighted_class_presence"]["lowercase"] == 1
    serialized = json.dumps(profile, ensure_ascii=False)
    assert "żółć123!" not in serialized


def test_run_profile_writes_json_report(tmp_path):
    target = tmp_path / "target.txt"
    output = tmp_path / "reports" / "pcfg.json"
    target.write_text("password123\n", encoding="utf-8")

    profile = run_profile(target, output)

    assert output.is_file()
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded == profile
    assert loaded["schema"] == "ruleops.pcfg-profile.v1"


def test_profile_reports_weighted_and_unweighted_distributions(tmp_path):
    target = tmp_path / "weighted.txt"
    target.write_text("3 abc123\n1 ABC!!!\nabc123\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input"]["profiled_entries"] == 3
    assert profile["input"]["weighted_observations"] == 5
    assert profile["length"]["unweighted_histogram"]["2-7"] == 3
    assert profile["length"]["weighted_histogram"]["2-7"] == 5
    assert profile["composition"]["unweighted_class_combinations"]["lowercase+digits"] == 2
    assert profile["composition"]["weighted_class_combinations"]["lowercase+digits"] == 4
    assert profile["profile_consistency"]["valid"] is True


def test_profile_reports_classification_coverage_and_diversity(tmp_path):
    target = tmp_path / "coverage.txt"
    target.write_text("abc\n१२३\nABC123\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input_coverage"]["profiled_entries"] == 3
    assert profile["input_coverage"]["nonempty_lines"] == 3
    assert profile["input_coverage"]["entry_acceptance_rate"] == 100.0
    assert profile["diversity"]["unweighted_class_combinations"]["observed_categories"] == 3
    assert profile["profile_consistency"]["valid"] is True


def test_compare_profiles_uses_separate_weighted_and_unweighted_denominators(tmp_path):
    reference_path = tmp_path / "reference.txt"
    candidate_path = tmp_path / "candidate.txt"
    reference_path.write_text("3 abc123\nzxyABC\n", encoding="utf-8")
    candidate_path.write_text("abc\n4 123\n", encoding="utf-8")

    reference = profile_wordlist(reference_path)
    candidate = profile_wordlist(candidate_path)
    comparison = compare_profiles(reference, candidate)

    assert comparison["schema"] == "ruleops.pcfg-profile-comparison.v1"
    assert comparison["class_combination_distribution_delta_percentage_points"]["weighted"]["digits"] == 80.0
    assert comparison["class_combination_distribution_delta_percentage_points"]["unweighted"]["digits"] == 50.0
    assert comparison["profile_consistency"] == {"reference_valid": True, "candidate_valid": True}


def test_run_profile_embeds_comparison_without_overwriting_profile_fields(tmp_path):
    target = tmp_path / "candidate.txt"
    reference_path = tmp_path / "reference.json"
    output = tmp_path / "candidate-profile.json"
    target.write_text("password123\n", encoding="utf-8")
    reference_profile = profile_wordlist(target)
    reference_path.write_text(json.dumps(reference_profile), encoding="utf-8")

    profile = run_profile(target, output, compare_path=reference_path)

    assert profile["schema"] == "ruleops.pcfg-profile.v1"
    assert profile["comparison"]["schema"] == "ruleops.pcfg-profile-comparison.v1"
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded == profile


def test_profile_consistency_flags_modified_histogram(tmp_path):
    from rulest.pcfg_profile import _consistency_checks

    target = tmp_path / "target.txt"
    target.write_text("abc123\n", encoding="utf-8")
    profile = profile_wordlist(target)
    profile["length"]["weighted_histogram"]["2-7"] += 1

    consistency = _consistency_checks(profile)

    assert consistency["valid"] is False
    assert consistency["checks"]["weighted_length_histogram_matches_total"] is False
    assert consistency["checks"]["weighted_policy_indicators_match_total"] is True


def test_compare_profiles_supports_earlier_v1_profile_without_unweighted_metrics(tmp_path):
    target = tmp_path / "candidate.txt"
    target.write_text("abc123\n", encoding="utf-8")
    candidate = profile_wordlist(target)
    reference = {
        "schema": "ruleops.pcfg-profile.v1",
        "profile_type": "aggregate_password_composition",
        "input": {"file_name": "older.json", "profiled_entries": 1, "weighted_observations": 2},
        "length": {"weighted_mean": 6.0, "weighted_histogram": {"2-7": 2}},
        "composition": {
            "weighted_class_combinations": {"lowercase+digits": 2},
            "weighted_class_presence": {"lowercase": 2, "digits": 2},
        },
    }

    comparison = compare_profiles(reference, candidate)

    assert comparison["length_distribution_delta_percentage_points"]["weighted"]["2-7"] == 0.0
    assert comparison["length_distribution_delta_percentage_points"]["unweighted"] is None
    assert comparison["class_diversity_delta"]["weighted_class_combinations"] is None
    assert comparison["class_diversity_delta"]["unweighted_class_combinations"] is None
    assert comparison["profile_consistency"]["reference_valid"] is None


def test_frequency_parser_accepts_tabs_and_repeated_whitespace(tmp_path):
    target = tmp_path / "frequency-whitespace.txt"
    target.write_text("5\t\talpha123\n2   Beta!!!\n", encoding="utf-8")

    profile = profile_wordlist(target)

    assert profile["input"]["profiled_entries"] == 2
    assert profile["input"]["weighted_observations"] == 7
    assert profile["composition"]["weighted_class_combinations"]["lowercase+digits"] == 5
    assert profile["composition"]["weighted_class_combinations"]["lowercase+uppercase+symbols"] == 2
    assert profile["profile_consistency"]["valid"] is True


def test_cli_prints_summary_and_comparison_status(tmp_path, capsys):
    target = tmp_path / "target.txt"
    reference = tmp_path / "reference.json"
    output = tmp_path / "profile.json"
    target.write_text("abc123\n", encoding="utf-8")
    reference.write_text(json.dumps(profile_wordlist(target)), encoding="utf-8")

    result = main([str(target), "--compare", str(reference), "--output", str(output)])

    captured = capsys.readouterr()
    assert result == 0
    assert "input coverage: accepted=100.00%" in captured.out
    assert "comparison: included in report" in captured.out




def test_weight_diagnostics_report_distribution_and_concentration(tmp_path):
    target = tmp_path / "weight-diagnostics.txt"
    target.write_text("10 abc\n20 ABC\n1 xyz\n", encoding="utf-8")

    profile = profile_wordlist(target)
    weights = profile["weight_diagnostics"]

    assert weights["profiled_weight_entries"] == 3
    assert weights["weight_min"] == 1
    assert weights["weight_max"] == 20
    assert weights["mean_weight_per_entry"] == 10.333333
    assert weights["weight_magnitude_histogram"] == {"1": 1, "8-15": 1, "16-31": 1}
    assert weights["top_weight_concentration"]["top_1"]["weight_sum"] == 20
    assert weights["top_weight_concentration"]["top_10"]["weight_sum"] == 31
    assert weights["weight_median_approx"]["bucket"] == "8-15"
    assert profile["profile_consistency"]["valid"] is True


def test_large_frequency_counts_do_not_overflow_int64(tmp_path):
    target = tmp_path / "very-large-weight.txt"
    huge_weight = (1 << 63)
    target.write_text(f"{huge_weight} Ab\n", encoding="utf-8")

    profile = profile_wordlist(target, input_format="count-value")
    diagnostics = profile["weight_diagnostics"]
    safety = diagnostics["integer_safety"]

    assert profile["input"]["weighted_observations"] == huge_weight
    assert diagnostics["weight_max"] == huge_weight
    assert safety["weighted_total_exceeds_signed_int64"] is True
    assert safety["max_single_weight_exceeds_signed_int64"] is True
    assert safety["entries_exceeding_signed_int64"] == 1
    assert safety["weighted_total_exceeds_safe_json_integer"] is True
    assert safety["entries_exceeding_safe_json_integer"] == 1
    assert profile["profile_consistency"]["valid"] is True


def test_plain_input_format_does_not_parse_leading_number_as_weight(tmp_path):
    target = tmp_path / "plain-numeric-prefix.txt"
    target.write_text("123 ABC\n", encoding="utf-8")

    profile = profile_wordlist(target, input_format="plain")

    assert profile["input"]["weighted_observations"] == 1
    assert profile["input"]["profiled_entries"] == 1
    assert profile["input"]["plain_records"] == 1
    assert profile["input"]["frequency_records"] == 0
    assert profile["length"]["unweighted_mean"] == 7.0
    assert profile["composition"]["unweighted_class_combinations"]["uppercase+digits+symbols"] == 1
    assert profile["profile_consistency"]["valid"] is True


def test_count_value_format_accounts_for_malformed_and_zero_weight_lines(tmp_path):
    target = tmp_path / "strict-frequency.txt"
    target.write_text("0 abc\n4 abcd\nnot-a-count\n", encoding="utf-8")

    profile = profile_wordlist(target, input_format="count-value")

    assert profile["input"]["profiled_entries"] == 1
    assert profile["input"]["weighted_observations"] == 4
    assert profile["input"]["zero_weight_entries"] == 1
    assert profile["input"]["malformed_frequency_entries"] == 1
    assert profile["profile_consistency"]["valid"] is True


def test_cli_accepts_explicit_plain_input_format(tmp_path, capsys):
    target = tmp_path / "plain.txt"
    output = tmp_path / "profile.json"
    target.write_text("123 ABC\n", encoding="utf-8")

    result = main([str(target), "--input-format", "plain", "--output", str(output)])

    assert result == 0
    assert json.loads(output.read_text(encoding="utf-8"))["input"]["weighted_observations"] == 1
    assert "weights: min=1 max=1" in capsys.readouterr().out
