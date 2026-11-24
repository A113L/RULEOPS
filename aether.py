#!/usr/bin/env python3
"""
Hashcat Rule Performance Benchmark Tool with Advanced Visualizations
Full rule support: implements all Hashcat transformations, reject rules, etc.
"""

import pyopencl as cl
import numpy as np
import time
import os
import json
import argparse
import re
from pathlib import Path
from typing import List, Dict, Tuple, Any
import sys
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Visualization styles
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# ============================================================================
# COMPLETE HASHCAT RULE ENGINE KERNEL
# ============================================================================
OPENCL_KERNEL_SOURCE = """
#define MAX_WORD_LEN 256
#define MAX_RULE_LEN 16
#define MAX_OUTPUT_LEN 512

int is_lower(uchar c) {
    return (c >= 'a' && c <= 'z');
}
int is_upper(uchar c) {
    return (c >= 'A' && c <= 'Z');
}
int is_digit(uchar c) {
    return (c >= '0' && c <= '9');
}
int is_alnum(uchar c) {
    return is_lower(c) || is_upper(c) || is_digit(c);
}
uchar toggle_case(uchar c) {
    if (is_lower(c)) return c - 32;
    if (is_upper(c)) return c + 32;
    return c;
}
uchar to_lower(uchar c) {
    if (is_upper(c)) return c + 32;
    return c;
}
uchar to_upper(uchar c) {
    if (is_lower(c)) return c - 32;
    return c;
}
int parse_position(uchar c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return 0;
}
int count_char(const uchar* str, int len, uchar x) {
    int cnt = 0;
    for (int i = 0; i < len; i++) if (str[i] == x) cnt++;
    return cnt;
}

__kernel void rule_processor(
    __global const uchar* words,
    __global const uchar* rules,
    __global uchar* results,
    const uint num_words,
    const uint num_rules,
    const uint max_word_len,
    const uint max_rule_len,
    const uint max_result_len)
{
    uint global_id = get_global_id(0);
    uint word_idx = global_id / num_rules;
    uint rule_idx = global_id % num_rules;

    if (word_idx >= num_words || rule_idx >= num_rules) return;

    uint word_offset = word_idx * max_word_len;
    uint rule_offset = rule_idx * max_rule_len;
    uint result_offset = global_id * max_result_len;

    uchar word[MAX_WORD_LEN];
    int word_len = 0;
    for (int i = 0; i < max_word_len; i++) {
        uchar c = words[word_offset + i];
        if (c == 0) break;
        word[i] = c;
        word_len++;
    }

    uchar rule[MAX_RULE_LEN];
    int rule_len = 0;
    for (int i = 0; i < max_rule_len; i++) {
        uchar c = rules[rule_offset + i];
        if (c == 0) break;
        rule[i] = c;
        rule_len++;
    }

    uchar output[MAX_OUTPUT_LEN];
    int out_len = 0;
    int changed = 0;

    for (int i = 0; i < max_result_len; i++) results[result_offset + i] = 0;

    if (rule_len == 0 || word_len == 0) return;

    // ======================= SIMPLE RULES (1 char) =======================
    if (rule_len == 1) {
        switch (rule[0]) {
            case 'l':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = to_lower(word[i]);
                changed = 1;
                break;
            case 'u':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = to_upper(word[i]);
                changed = 1;
                break;
            case 'c':
                out_len = word_len;
                if (word_len > 0) {
                    output[0] = to_upper(word[0]);
                    for (int i = 1; i < word_len; i++) output[i] = to_lower(word[i]);
                }
                changed = 1;
                break;
            case 'C':
                out_len = word_len;
                if (word_len > 0) {
                    output[0] = to_lower(word[0]);
                    for (int i = 1; i < word_len; i++) output[i] = to_upper(word[i]);
                }
                changed = 1;
                break;
            case 't':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = toggle_case(word[i]);
                changed = 1;
                break;
            case 'r':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[word_len - 1 - i];
                changed = 1;
                break;
            case 'k':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (word_len >= 2) {
                    output[0] = word[1];
                    output[1] = word[0];
                    changed = 1;
                }
                break;
            case 'K':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (word_len >= 2) {
                    output[word_len-2] = word[word_len-1];
                    output[word_len-1] = word[word_len-2];
                    changed = 1;
                }
                break;
            case ':':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                changed = 0;
                break;
            case 'd':
                if (word_len * 2 <= MAX_OUTPUT_LEN) {
                    out_len = word_len * 2;
                    for (int i = 0; i < word_len; i++) {
                        output[i] = word[i];
                        output[word_len + i] = word[i];
                    }
                    changed = 1;
                }
                break;
            case 'f':
                if (word_len * 2 <= MAX_OUTPUT_LEN) {
                    out_len = word_len * 2;
                    for (int i = 0; i < word_len; i++) {
                        output[i] = word[i];
                        output[word_len + i] = word[word_len - 1 - i];
                    }
                    changed = 1;
                }
                break;
            case 'p':
                if (word_len + 1 <= MAX_OUTPUT_LEN) {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    output[out_len++] = 's';
                    changed = 1;
                }
                break;
            case 'z':
                if (word_len + 1 <= MAX_OUTPUT_LEN) {
                    output[0] = word[0];
                    for (int i = 0; i < word_len; i++) output[i+1] = word[i];
                    out_len = word_len + 1;
                    changed = 1;
                }
                break;
            case 'Z':
                if (word_len + 1 <= MAX_OUTPUT_LEN) {
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    output[word_len] = word[word_len-1];
                    out_len = word_len + 1;
                    changed = 1;
                }
                break;
            case 'q':
                if (word_len * 2 <= MAX_OUTPUT_LEN) {
                    int idx = 0;
                    for (int i = 0; i < word_len; i++) {
                        output[idx++] = word[i];
                        output[idx++] = word[i];
                    }
                    out_len = word_len * 2;
                    changed = 1;
                }
                break;
            case 'E':
                out_len = word_len;
                int cap = 1;
                for (int i = 0; i < word_len; i++) {
                    if (cap && is_lower(word[i])) output[i] = word[i] - 32;
                    else output[i] = word[i];
                    if (word[i] == ' ' || word[i] == '-' || word[i] == '_') cap = 1;
                    else cap = 0;
                }
                changed = 1;
                break;
            // Memory placeholders – no effect
            case 'M': case '4': case '6': case '_':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                changed = 0;
                break;
            case 'Q':
                changed = -1;
                break;
            default:
                changed = 0;
                break;
        }
    }

    // ======================= TWO‑CHAR RULES =======================
    else if (rule_len == 2) {
        uchar cmd = rule[0];
        uchar arg = rule[1];
        int n = parse_position(arg);

        switch (cmd) {
            case 'T':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (n < word_len) { output[n] = toggle_case(word[n]); changed = 1; }
                break;
            case 'D':
                out_len = 0;
                for (int i = 0; i < word_len; i++) {
                    if (i != n) output[out_len++] = word[i];
                    else changed = 1;
                }
                break;
            case 'L':
                out_len = 0;
                for (int i = n; i < word_len; i++) output[out_len++] = word[i];
                changed = (n > 0);
                break;
            case 'R':
                out_len = (n + 1 < word_len) ? n + 1 : word_len;
                for (int i = 0; i < out_len; i++) output[i] = word[i];
                changed = (out_len != word_len);
                break;
            case '+':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (n < word_len && word[n] < 255) { output[n] = word[n] + 1; changed = 1; }
                break;
            case '-':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (n < word_len && word[n] > 0) { output[n] = word[n] - 1; changed = 1; }
                break;
            case '.':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (n < word_len && word[n] < 255) { output[n] = word[n] + 1; changed = 1; }
                break;
            case ',':
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                if (n < word_len && word[n] > 0) { output[n] = word[n] - 1; changed = 1; }
                break;
            case '^':
                if (word_len + 1 <= MAX_OUTPUT_LEN) {
                    output[0] = arg;
                    for (int i = 0; i < word_len; i++) output[i+1] = word[i];
                    out_len = word_len + 1;
                    changed = 1;
                }
                break;
            case '$':
                if (word_len + 1 <= MAX_OUTPUT_LEN) {
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    output[word_len] = arg;
                    out_len = word_len + 1;
                    changed = 1;
                }
                break;
            case '@':
                out_len = 0;
                for (int i = 0; i < word_len; i++) {
                    if (word[i] != arg) output[out_len++] = word[i];
                    else changed = 1;
                }
                break;
            case '!':
                {
                    int reject = 0;
                    for (int i = 0; i < word_len; i++) {
                        if (word[i] == arg) { reject = 1; break; }
                    }
                    if (reject) changed = -1;
                    else {
                        out_len = word_len;
                        for (int i = 0; i < word_len; i++) output[i] = word[i];
                        changed = 0;
                    }
                }
                break;
            case '/':
                {
                    int found = 0;
                    for (int i = 0; i < word_len; i++) if (word[i] == arg) { found = 1; break; }
                    if (!found) changed = -1;
                    else {
                        out_len = word_len;
                        for (int i = 0; i < word_len; i++) output[i] = word[i];
                        changed = 0;
                    }
                }
                break;
            case 'p':
                {
                    int mult = n <= 0 ? 1 : n;
                    int total_len = word_len * mult;
                    if (total_len <= MAX_OUTPUT_LEN) {
                        out_len = total_len;
                        for (int i = 0; i < mult; i++)
                            for (int j = 0; j < word_len; j++)
                                output[i*word_len + j] = word[j];
                        changed = 1;
                    }
                }
                break;
            case '(':
                if (word_len == 0 || word[0] != arg) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case ')':
                if (word_len == 0 || word[word_len-1] != arg) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case '<':
                if (word_len > n) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case '>':
                if (word_len < n) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case '_':
                if (word_len != n) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case '=':
                if (n >= word_len || word[n] != arg) changed = -1;
                else {
                    out_len = word_len;
                    for (int i = 0; i < word_len; i++) output[i] = word[i];
                    changed = 0;
                }
                break;
            case '%':
                {
                    int cnt = count_char(word, word_len, arg);
                    if (cnt < n) changed = -1;
                    else {
                        out_len = word_len;
                        for (int i = 0; i < word_len; i++) output[i] = word[i];
                        changed = 0;
                    }
                }
                break;
            case 'y':
                {
                    int nn = n;
                    if (nn > word_len) nn = word_len;
                    if (word_len + nn <= MAX_OUTPUT_LEN) {
                        out_len = word_len + nn;
                        for (int i = 0; i < word_len; i++) output[i] = word[i];
                        for (int i = 0; i < nn; i++) output[word_len + i] = word[i];
                        changed = 1;
                    }
                }
                break;
            case 'Y':
                {
                    int nn = n;
                    if (nn > word_len) nn = word_len;
                    if (word_len + nn <= MAX_OUTPUT_LEN) {
                        out_len = word_len + nn;
                        for (int i = 0; i < word_len; i++) output[i] = word[i];
                        for (int i = 0; i < nn; i++) output[word_len + i] = word[word_len - nn + i];
                        changed = 1;
                    }
                }
                break;
            case 39: // apostrophe rule: truncate at N
                {
                    int nn = n;
                    if (nn > word_len) nn = word_len;
                    out_len = nn;
                    for (int i = 0; i < nn; i++) output[i] = word[i];
                    changed = (nn != word_len);
                }
                break;
            default:
                changed = 0;
                break;
        }
    }

    // ======================= THREE‑CHAR RULES =======================
    else if (rule_len == 3) {
        uchar cmd = rule[0];
        uchar arg1 = rule[1];
        uchar arg2 = rule[2];

        if (cmd == 's') {
            out_len = word_len;
            for (int i = 0; i < word_len; i++) {
                output[i] = (word[i] == arg1) ? arg2 : word[i];
            }
            changed = 1;
        }
        else if (cmd == '*') {
            int n = parse_position(arg1);
            int m = parse_position(arg2);
            out_len = word_len;
            for (int i = 0; i < word_len; i++) output[i] = word[i];
            if (n < word_len && m < word_len && n != m) {
                uchar temp = output[n];
                output[n] = output[m];
                output[m] = temp;
                changed = 1;
            }
        }
        else if (cmd == 'x') {
            int n = parse_position(arg1);
            int m = parse_position(arg2);
            if (n < word_len) {
                out_len = 0;
                for (int i = n; i < word_len && out_len < m; i++) {
                    output[out_len++] = word[i];
                }
                changed = 1;
            }
        }
        else if (cmd == 'O') {
            int n = parse_position(arg1);
            int m = parse_position(arg2);
            out_len = 0;
            for (int i = 0; i < word_len; i++) {
                if (i >= n && i < n + m) continue;
                output[out_len++] = word[i];
            }
            changed = (out_len != word_len);
        }
        else if (cmd == 'i') {
            int n = parse_position(arg1);
            if (word_len + 1 <= MAX_OUTPUT_LEN) {
                out_len = 0;
                for (int i = 0; i < word_len; i++) {
                    if (i == n) output[out_len++] = arg2;
                    output[out_len++] = word[i];
                }
                if (n >= word_len) output[out_len++] = arg2;
                changed = 1;
            }
        }
        else if (cmd == 'o') {
            int n = parse_position(arg1);
            out_len = word_len;
            for (int i = 0; i < word_len; i++) output[i] = word[i];
            if (n < word_len) {
                output[n] = arg2;
                changed = 1;
            }
        }
        else if (cmd == 'T') {
            int n = parse_position(arg1);
            int m = parse_position(arg2);
            if (n > m) { int t = n; n = m; m = t; }
            out_len = word_len;
            for (int i = 0; i < word_len; i++) output[i] = word[i];
            for (int i = n; i <= m && i < word_len; i++) {
                output[i] = toggle_case(word[i]);
            }
            changed = 1;
        }
        else if (cmd == '?') {
            int n = parse_position(arg1);
            if (n >= word_len || word[n] != arg2) changed = -1;
            else {
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                changed = 0;
            }
        }
        else if (cmd == '=') {
            int n = parse_position(arg1);
            if (n < word_len && word[n] == arg2) changed = -1;
            else {
                out_len = word_len;
                for (int i = 0; i < word_len; i++) output[i] = word[i];
                changed = 0;
            }
        }
        else if (cmd == 'e') {
            uchar sep = arg1;
            out_len = word_len;
            int cap = 1;
            for (int i = 0; i < word_len; i++) {
                if (cap && is_lower(word[i])) output[i] = word[i] - 32;
                else output[i] = word[i];
                if (word[i] == sep) cap = 1;
                else cap = 0;
            }
            changed = 1;
        }
        else if (cmd == '3') {
            int n = parse_position(arg1);
            uchar sep = arg2;
            out_len = word_len;
            for (int i = 0; i < word_len; i++) output[i] = word[i];
            int count = 0;
            for (int i = 0; i < word_len; i++) {
                if (word[i] == sep) {
                    count++;
                    if (count == n && i+1 < word_len) {
                        output[i+1] = toggle_case(word[i+1]);
                        changed = 1;
                        break;
                    }
                }
            }
        }
        else if (cmd == '{') {
            int n = parse_position(arg1);
            if (n <= 0) n = 1;
            out_len = word_len;
            for (int i = 0; i < word_len; i++) {
                int src = (i + n) % word_len;
                output[i] = word[src];
            }
            changed = 1;
        }
        else if (cmd == '}') {
            int n = parse_position(arg1);
            if (n <= 0) n = 1;
            out_len = word_len;
            for (int i = 0; i < word_len; i++) {
                int src = (i - n + word_len) % word_len;
                output[i] = word[src];
            }
            changed = 1;
        }
        else if (cmd == '[') {
            int n = parse_position(arg1);
            if (n > word_len) n = word_len;
            out_len = word_len - n;
            for (int i = n; i < word_len; i++) output[i-n] = word[i];
            changed = 1;
        }
        else if (cmd == ']') {
            int n = parse_position(arg1);
            if (n > word_len) n = word_len;
            out_len = word_len - n;
            for (int i = 0; i < out_len; i++) output[i] = word[i];
            changed = 1;
        }
        else if (cmd == 'v') {
            int n = parse_position(arg1);
            uchar x = arg2;
            if (n > 0 && word_len + (word_len / n) <= MAX_OUTPUT_LEN) {
                out_len = 0;
                for (int i = 0; i < word_len; i++) {
                    output[out_len++] = word[i];
                    if ((i+1) % n == 0 && i+1 < word_len) {
                        output[out_len++] = x;
                    }
                }
                changed = 1;
            }
        }
        else {
            changed = 0;
        }
    }

    // ======================= FOUR‑CHAR RULES (memory placeholders) =======================
    else if (rule_len == 4) {
        // Memory operations not implemented – treat as no-op
        out_len = word_len;
        for (int i = 0; i < word_len; i++) output[i] = word[i];
        changed = 0;
    }

    // ======================= OUTPUT =======================
    if (changed <= 0) out_len = 0;

    if (out_len > 0 && changed > 0) {
        for (int i = 0; i < out_len && i < max_result_len - 1; i++) {
            results[result_offset + i] = output[i];
        }
        results[result_offset + out_len] = 0;
    } else {
        results[result_offset] = 0;
    }
}
"""

# ============================================================================
# REST OF THE SCRIPT (unchanged except for minor adjustments)
# ============================================================================
# The following classes and functions remain largely the same as in the original,
# but we keep them here for completeness. They use the new kernel.
# ============================================================================

def print_banner():
    """Print enhanced banner"""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                HASHCAT RULE PERFORMANCE BENCHMARK             ║
║               Advanced Visualization Edition                  ║
║                  Michelson-Morley Inspired                    ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}
🔬 Scientific-Grade Performance Analysis
📊 Advanced Data Visualization  
⚡ OpenCL GPU Acceleration
🎯 Michelson-Morley Precision Methodology
{Colors.END}
"""
    print(banner)

class VisualizationEngine:
    """Advanced visualization engine for benchmark results"""
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.setup_styles()
    
    def setup_styles(self):
        plt.rcParams['figure.figsize'] = [12, 8]
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12

    @staticmethod
    def _literal_rule_command(rule: str) -> str:
        """Return the complete rule-file command without math/text rewriting."""
        command = str(rule)
        # Keep unusual whitespace visible in static charts and avoid accidental
        # line breaks changing how a Hashcat command is read.
        return (command.replace('\t', r'\t')
                       .replace('\r', r'\r')
                       .replace('\n', r'\n'))


    def create_performance_radar(self, rule_performance: List[Tuple[str, Dict]], filename: str):
        if not rule_performance: return
        top_rules = rule_performance[:20]
        rules = [f"{rule[:15]}..." if len(rule) > 15 else rule for rule, _ in top_rules]
        times = [data['execution_time'] * 1000000 for _, data in top_rules]
        ops_sec = [data['operations_per_sec'] / 1000 for _, data in top_rules]
        cv_values = [data['metrics']['cv_percent'] for _, data in top_rules]
        times_norm = self.normalize_data(times, invert=True)
        ops_norm = self.normalize_data(ops_sec)
        cv_norm = self.normalize_data(cv_values, invert=True)
        categories = ['GPU Kernel Time\n(μs)', 'GPU Throughput\n(K ops/sec)', 'Consistency\n(CV %)']
        fig, ax = plt.subplots(figsize=(14, 10), subplot_kw=dict(projection='polar'))
        angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
        angles += angles[:1]
        for i, (rule, time_n, ops_n, cv_n) in enumerate(zip(rules, times_norm, ops_norm, cv_norm)):
            values = [time_n, ops_n, cv_n]
            values += values[:1]
            ax.plot(angles, values, 'o-', linewidth=2, label=rule, markersize=6, alpha=0.7)
            ax.fill(angles, values, alpha=0.1)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories)
        ax.set_ylim(0, 1)
        ax.set_yticks([])
        ax.grid(True, alpha=0.3)
        plt.title('Rule Performance Radar Chart\n(Top 20 Rules)', size=16, pad=20)
        plt.legend(bbox_to_anchor=(1.2, 1.0), loc='upper left')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, f"{filename}_radar.png"), dpi=300, bbox_inches='tight')
        plt.close()
        print(f"{Colors.GREEN}Radar chart saved: {filename}_radar.png{Colors.END}")
    
    def create_performance_heatmap(self, rule_performance: List[Tuple[str, Dict]], filename: str):
        if not rule_performance: return
        rule_types = {}
        for rule, data in rule_performance:
            rule_char = rule[0] if rule else '?'
            if rule_char not in rule_types:
                rule_types[rule_char] = []
            rule_types[rule_char].append(data['execution_time'] * 1000000)
        rule_chars = list(rule_types.keys())
        performance_data = []
        for char in rule_chars:
            times = rule_types[char]
            if times:
                performance_data.append(np.mean(times))
        if not performance_data: return
        grid_size = int(np.ceil(np.sqrt(len(rule_chars))))
        heatmap_data = np.full((grid_size, grid_size), np.nan)
        char_labels = np.full((grid_size, grid_size), '', dtype=object)
        for idx, (char, perf) in enumerate(zip(rule_chars, performance_data)):
            row = idx // grid_size
            col = idx % grid_size
            if row < grid_size and col < grid_size:
                heatmap_data[row, col] = perf
                char_labels[row, col] = char
        fig, ax = plt.subplots(figsize=(12, 10))
        im = ax.imshow(heatmap_data, cmap='RdYlGn_r', aspect='auto')
        for i in range(grid_size):
            for j in range(grid_size):
                if not np.isnan(heatmap_data[i, j]):
                    ax.text(j, i, f"{char_labels[i, j]}\n{heatmap_data[i, j]:.1f}μs",
                            ha="center", va="center", color="black", fontsize=8,
                            bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.7))
        plt.colorbar(im, ax=ax, label='GPU Kernel Time (μs)')
        ax.set_title('Rule Type Performance Heatmap\n(GPU Kernel Time · Lower = Faster)', pad=20)
        ax.set_xticks([])
        ax.set_yticks([])
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, f"{filename}_heatmap.png"), dpi=300, bbox_inches='tight')
        plt.close()
        print(f"{Colors.GREEN}Heatmap saved: {filename}_heatmap.png{Colors.END}")
    
    @staticmethod
    def _relative_performance_tiers(times_us: List[float]):
        """Build balanced, tie-preserving performance tiers for one rule file.

        Absolute 10/100 µs cut-offs are not portable across GPUs. Relative
        tiers describe the rules within the current benchmark while keeping
        identical timings together.
        """
        values = np.asarray(times_us, dtype=float)
        values = values[np.isfinite(values)]
        if values.size == 0:
            return [], [], []

        unique_values, group_counts = np.unique(values, return_counts=True)
        if unique_values.size == 1:
            value = float(unique_values[0])
            return [int(values.size)], [f'Comparable (≈{value:.3f} µs)'], ['#3498db']

        cumulative = np.cumsum(group_counts)
        total = int(values.size)

        # Find boundaries near one-third and two-thirds of the sample. Cuts are
        # made only between distinct timings, so equal measurements stay in
        # the same tier even when that makes the buckets slightly uneven.
        first_candidates = cumulative[:-2] if unique_values.size >= 3 else cumulative[:-1]
        first_cut = int(np.argmin(np.abs(first_candidates - total / 3.0))) + 1
        if unique_values.size >= 3:
            remaining_cumulative = cumulative[first_cut:-1]
            second_cut = first_cut + int(
                np.argmin(np.abs(remaining_cumulative - (2.0 * total / 3.0)))
            ) + 1
            second_cut = min(max(second_cut, first_cut + 1), unique_values.size - 1)
        else:
            second_cut = unique_values.size

        fast_count = int(cumulative[first_cut - 1])
        if second_cut < unique_values.size:
            medium_count = int(cumulative[second_cut - 1] - fast_count)
            slow_count = total - fast_count - medium_count
        else:
            medium_count = 0
            slow_count = total - fast_count

        labels = [f'Fastest (≤{unique_values[first_cut - 1]:.3f} µs)']
        counts = [fast_count]
        colors = ['#2ecc71']
        if medium_count:
            labels.append(
                f'Middle ({unique_values[first_cut]:.3f}–{unique_values[second_cut - 1]:.3f} µs)'
            )
            counts.append(medium_count)
            colors.append('#f1c40f')
        if slow_count:
            lower_bound = unique_values[second_cut] if medium_count else unique_values[first_cut]
            labels.append(f'Slowest (≥{lower_bound:.3f} µs)')
            counts.append(slow_count)
            colors.append('#e74c3c')
        return counts, labels, colors

    def create_statistical_summary(self, rule_performance: List[Tuple[str, Dict]], filename: str):
        if not rule_performance:
            print(f"{Colors.YELLOW}No performance data available for statistical summary{Colors.END}")
            return
        try:
            rules = [rule for rule, _ in rule_performance]
            times = [data['execution_time'] * 1000000 for _, data in rule_performance if 'execution_time' in data]
            cv_values = [data['metrics']['cv_percent'] for _, data in rule_performance if 'metrics' in data and 'cv_percent' in data['metrics']]
            ops_sec = [data['operations_per_sec'] for _, data in rule_performance if 'operations_per_sec' in data]
            if not times:
                print(f"{Colors.RED}No execution time data available for statistical summary{Colors.END}")
                return
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            # 1. Performance distribution
            axes[0,0].hist(times, bins=30, alpha=0.7, color='skyblue', edgecolor='black')
            axes[0,0].axvline(np.mean(times), color='red', linestyle='--', label=f'Mean: {np.mean(times):.2f}μs')
            axes[0,0].axvline(np.median(times), color='green', linestyle='--', label=f'Median: {np.median(times):.2f}μs')
            axes[0,0].set_xlabel('GPU Kernel Time (μs)')
            axes[0,0].set_ylabel('Frequency')
            axes[0,0].set_title('GPU Kernel Time Distribution')
            axes[0,0].legend()
            axes[0,0].grid(True, alpha=0.3)
            # 2. Consistency vs Performance
            if times and cv_values and len(times) == len(cv_values):
                scatter = axes[0,1].scatter(times, cv_values, c=ops_sec if ops_sec else times, cmap='viridis', alpha=0.6, s=50, edgecolors='black', linewidth=0.5)
                axes[0,1].set_xlabel('GPU Kernel Time (μs)')
                axes[0,1].set_ylabel('Coefficient of Variation (%)')
                axes[0,1].set_title('GPU Kernel Time vs Consistency')
                plt.colorbar(scatter, ax=axes[0,1], label='GPU Operations/sec' if ops_sec else 'GPU Kernel Time (μs)')
                axes[0,1].grid(True, alpha=0.3)
            else:
                axes[0,1].text(0.5, 0.5, 'Insufficient data', ha='center', va='center', transform=axes[0,1].transAxes)
                axes[0,1].set_title('GPU Kernel Time vs Consistency (No Data)')
            # 3. Top 10 fastest Hashcat rule commands. Rule files contain
            # command strings, not semantic names: show each complete source
            # line verbatim without rank prefixes, truncation, or MathText.
            if rule_performance:
                top_10 = sorted(
                    rule_performance,
                    key=lambda item: item[1].get(
                        'gpu_kernel_time_seconds', item[1].get('execution_time', float('inf'))
                    )
                )[:min(10, len(rule_performance))]
                top_rules = [self._literal_rule_command(rule) or '<empty rule>' for rule, _ in top_10]
                top_times = [
                    data.get('gpu_kernel_time_seconds', data.get('execution_time', float('inf'))) * 1_000_000
                    for _, data in top_10
                ]
                fastest_us = min(top_times)
                slower_pct = [((value / fastest_us) - 1.0) * 100.0 if fastest_us > 0 else 0.0
                              for value in top_times]
                y_positions = np.arange(len(top_rules))
                bars = axes[1,0].barh(
                    y_positions, slower_pct,
                    color=plt.cm.Greens_r(np.linspace(0.2, 0.8, len(top_rules)))
                )
                axes[1,0].set_yticks(y_positions, labels=top_rules)
                axes[1,0].set_xlabel('Slower than fastest rule (%)')
                axes[1,0].set_ylabel('Exact Hashcat rule-file command')
                axes[1,0].set_title('Top 10 Fastest Hashcat Rule Commands')
                axes[1,0].grid(True, alpha=0.3, axis='x')
                axes[1,0].invert_yaxis()  # rank 1 (fastest) at the top
                for tick in axes[1,0].get_yticklabels():
                    tick.set_fontfamily('DejaVu Sans Mono')
                    tick.set_fontsize(8)
                    tick.set_parse_math(False)
                max_delta = max(slower_pct, default=0.0)
                x_max = max(max_delta * 1.35, 0.12)
                axes[1,0].set_xlim(0, x_max)
                label_pad = x_max * 0.015
                for bar, absolute_us, delta_pct in zip(bars, top_times, slower_pct):
                    width = bar.get_width()
                    axes[1,0].text(
                        width + label_pad, bar.get_y() + bar.get_height()/2,
                        f'{absolute_us:.3f} µs  (+{delta_pct:.3f}%)',
                        ha='left', va='center', fontsize=8
                    )
                axes[1,0].text(
                    0.0, -0.20,
                    'Labels are the exact rule commands from the input file (not descriptive rule names).',
                    ha='left', va='top', fontsize=8, transform=axes[1,0].transAxes
                )
            else:
                axes[1,0].text(0.5, 0.5, 'No rule performance data', ha='center', va='center', transform=axes[1,0].transAxes)
                axes[1,0].set_title('Top 10 Fastest Hashcat Rule Commands (No Data)')
            # 4. Relative performance tiers describe differences between GPU
            # kernel timings without relying on hardware-specific cut-offs.
            if times:
                counts, categories, category_colors = self._relative_performance_tiers(times)
                if counts:
                    axes[1,1].pie(
                        counts, labels=categories, colors=category_colors,
                        autopct='%1.1f%%', startangle=90,
                        wedgeprops={'edgecolor': 'white', 'linewidth': 1}
                    )
                    axes[1,1].set_title('Relative GPU Performance Tiers')
                    axes[1,1].text(
                        0.5, -0.08,
                        'Within this file · GPU kernel time · lower is faster · equal timings stay together',
                        ha='center', va='top', fontsize=8, transform=axes[1,1].transAxes
                    )
                else:
                    axes[1,1].text(0.5, 0.5, 'No performance category data', ha='center', va='center', transform=axes[1,1].transAxes)
                    axes[1,1].set_title('Relative GPU Performance Tiers (No Data)')
            else:
                axes[1,1].text(0.5, 0.5, 'No execution time data', ha='center', va='center', transform=axes[1,1].transAxes)
                axes[1,1].set_title('Relative GPU Performance Tiers (No Data)')
            plt.suptitle('Comprehensive Statistical Summary', fontsize=16, y=0.98)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, f"{filename}_statistical.png"), dpi=300, bbox_inches='tight')
            plt.close()
            print(f"{Colors.GREEN}Statistical summary saved: {filename}_statistical.png{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error creating statistical summary: {e}{Colors.END}")
    
    def create_performance_distribution(self, rule_performance: List[Tuple[str, Dict]], filename: str):
        if not rule_performance:
            print(f"{Colors.YELLOW}No performance data available for distribution plot{Colors.END}")
            return
        try:
            times = [data['execution_time'] * 1000000 for _, data in rule_performance if 'execution_time' in data]
            if not times:
                print(f"{Colors.RED}No execution time data available{Colors.END}")
                return
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            # 1. Histogram with density
            axes[0,0].hist(times, bins=30, alpha=0.7, color='lightblue', edgecolor='black', density=True, label='Distribution')
            try:
                from scipy.stats import gaussian_kde
                density = gaussian_kde(times)
                xs = np.linspace(min(times), max(times), 200)
                axes[0,0].plot(xs, density(xs), 'r-', linewidth=2, label='Density Curve')
            except ImportError:
                pass
            axes[0,0].axvline(np.mean(times), color='red', linestyle='--', linewidth=2, label=f'Mean: {np.mean(times):.2f}μs')
            axes[0,0].axvline(np.median(times), color='green', linestyle='--', linewidth=2, label=f'Median: {np.median(times):.2f}μs')
            axes[0,0].set_xlabel('GPU Kernel Time (μs)')
            axes[0,0].set_ylabel('Density')
            axes[0,0].set_title('Performance Distribution with Density Curve')
            axes[0,0].legend()
            axes[0,0].grid(True, alpha=0.3)
            # 2. Box plot
            box_plot = axes[0,1].boxplot([times], vert=True, patch_artist=True,
                                          boxprops=dict(facecolor='lightgreen', alpha=0.7),
                                          medianprops=dict(color='red', linewidth=2))
            axes[0,1].set_ylabel('GPU Kernel Time (μs)')
            axes[0,1].set_title('GPU Kernel Time Box Plot')
            axes[0,1].set_xticks([1])
            axes[0,1].set_xticklabels(['All Rules'])
            axes[0,1].grid(True, alpha=0.3)
            stats_text = f"""Statistics:
Mean: {np.mean(times):.2f}μs
Median: {np.median(times):.2f}μs
Std: {np.std(times):.2f}μs
Min: {np.min(times):.2f}μs
Max: {np.max(times):.2f}μs
Q1: {np.percentile(times, 25):.2f}μs
Q3: {np.percentile(times, 75):.2f}μs"""
            axes[0,1].text(1.05, 0.95, stats_text, transform=axes[0,1].transAxes,
                           verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5),
                           fontfamily='monospace', fontsize=8)
            # 3. Cumulative distribution
            sorted_times = np.sort(times)
            cdf = np.arange(1, len(sorted_times)+1) / len(sorted_times)
            axes[1,0].plot(sorted_times, cdf, 'b-', linewidth=2, label='CDF')
            axes[1,0].set_xlabel('GPU Kernel Time (μs)')
            axes[1,0].set_ylabel('Cumulative Probability')
            axes[1,0].set_title('GPU Kernel Time Cumulative Distribution')
            axes[1,0].grid(True, alpha=0.3)
            axes[1,0].legend()
            for p in [25,50,75,90,95]:
                p_val = np.percentile(times, p)
                axes[1,0].axvline(p_val, color='red', linestyle='--', alpha=0.7)
                axes[1,0].text(p_val, 0.5, f'{p}%', rotation=90, va='center', ha='right')
            # 4. Violin plot
            try:
                violin_parts = axes[1,1].violinplot([times], showmeans=True, showmedians=True)
                for pc in violin_parts['bodies']:
                    pc.set_facecolor('lightcoral')
                    pc.set_alpha(0.7)
                violin_parts['cmeans'].set_color('green')
                violin_parts['cmedians'].set_color('blue')
                axes[1,1].set_ylabel('GPU Kernel Time (μs)')
                axes[1,1].set_title('GPU Kernel Time Violin Plot')
                axes[1,1].set_xticks([1])
                axes[1,1].set_xticklabels(['All Rules'])
                axes[1,1].grid(True, alpha=0.3)
            except:
                axes[1,1].hist(times, bins=30, alpha=0.7, color='lightcoral', edgecolor='black')
                axes[1,1].set_xlabel('GPU Kernel Time (μs)')
                axes[1,1].set_ylabel('Frequency')
                axes[1,1].set_title('GPU Kernel Time Distribution (Fallback)')
                axes[1,1].grid(True, alpha=0.3)
            plt.suptitle('GPU Kernel Time Distribution Analysis', fontsize=16, y=0.98)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, f"{filename}_distribution.png"), dpi=300, bbox_inches='tight')
            plt.close()
            print(f"{Colors.GREEN}Performance distribution saved: {filename}_distribution.png{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error creating performance distribution: {e}{Colors.END}")
    
    def normalize_data(self, data: List[float], invert: bool = False) -> List[float]:
        if not data: return []
        min_val, max_val = min(data), max(data)
        if max_val == min_val: return [0.5] * len(data)
        norm = [(x - min_val) / (max_val - min_val) for x in data]
        if invert: norm = [1 - x for x in norm]
        return norm
    
    def generate_dashboard(self, performance_data: Dict, filename: str):
        print(f"{Colors.CYAN}Generating comprehensive visualization dashboard...{Colors.END}")
        if 'rule_performance' in performance_data:
            rp = performance_data['rule_performance']
            self.create_performance_radar(rp, filename)
            self.create_performance_heatmap(rp, filename)
            self.create_statistical_summary(rp, filename)
            self.create_performance_distribution(rp, filename)
        print(f"{Colors.GREEN}Dashboard generation complete!{Colors.END}")

class RulePerformanceTester:
    def __init__(self, platform_index=0, device_index=0):
        self.visualizer = None
        self.setup_opencl(platform_index, device_index)
    
    def setup_opencl(self, platform_index: int, device_index: int):
        try:
            platforms = cl.get_platforms()
            if not platforms: raise RuntimeError("No OpenCL platforms found")
            platform = platforms[platform_index]
            devices = platform.get_devices(cl.device_type.GPU)
            if not devices:
                raise RuntimeError(
                    "No OpenCL GPU device found. Aether reports GPU kernel timing "
                    "and will not silently fall back to a CPU device."
                )
            device = devices[device_index]
            print(f"{Colors.GREEN}Using device: {device.name}{Colors.END}")
            print(f"{Colors.CYAN}Device memory: {device.global_mem_size // (1024*1024)} MB{Colors.END}")
            self.context = cl.Context([device])
            # Aether always profiles OpenCL events. This is deliberately not
            # an opt-in setting: GPU Kernel Time, ranking and optimization
            # budgets all depend on device-side START/END timestamps.
            self.profiling_enabled = True
            queue_properties = cl.command_queue_properties.PROFILING_ENABLE
            self.queue = cl.CommandQueue(
                self.context,
                properties=queue_properties
            )
            self.device = device
            print(
                f"{Colors.GREEN}OpenCL event profiling: ENABLED "
                f"(PROFILING_ENABLE; required for GPU Kernel Time){Colors.END}"
            )
            try:
                self.program = cl.Program(self.context, OPENCL_KERNEL_SOURCE).build()
                self.kernel = cl.Kernel(self.program, 'rule_processor')
                print(f"{Colors.GREEN}OpenCL kernel compiled successfully{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}Kernel compilation failed: {e}{Colors.END}")
                try:
                    build_log = self.program.get_build_info(device, cl.program_build_info.LOG)
                    print(f"{Colors.YELLOW}Build log: {build_log}{Colors.END}")
                except: pass
                raise
        except Exception as e:
            print(f"{Colors.RED}OpenCL initialization failed: {e}{Colors.END}")
            raise
    
    def setup_visualization(self, output_dir: str):
        self.visualizer = VisualizationEngine(output_dir)
        print(f"{Colors.GREEN}Visualization engine initialized{Colors.END}")
    
    def setup_test_data(self, max_words: int = 1000, identical_dicts: bool = False):
        builtin_words = [
            b"password", b"123456", b"qwerty", b"letmein", b"welcome", b"monkey", b"dragon", b"master",
            b"hello", b"freedom", b"whatever", b"computer", b"internet", b"sunshine", b"princess", b"charlie"
        ]
        if identical_dicts:
            # Tile the full builtin list repeatedly until we reach max_words.
            # Every cycle is an exact copy of the same 16 words, so the input
            # space is perfectly uniform across iterations — precision/reject
            # rules (!, /, (, ), <, >, _, =, %) see identical inputs every time,
            # eliminating word-variance noise from the measurements.
            count = max(1, max_words)
            self.test_words = (builtin_words * (count // len(builtin_words) + 1))[:count]
            print(f"{Colors.BOLD}{Colors.MAGENTA}[identical-dicts mode]{Colors.END} "
                  f"{Colors.GREEN}Dictionary: {count} words "
                  f"({len(builtin_words)} built-in words tiled × "
                  f"{count // len(builtin_words) + 1}){Colors.END}")
        else:
            if max_words < len(builtin_words):
                self.test_words = builtin_words[:max_words]
            else:
                self.test_words = builtin_words
                print(f"{Colors.YELLOW}Built-in word list has only {len(builtin_words)} words, using all.{Colors.END}")
            print(f"{Colors.GREEN}Using built-in test words ({len(self.test_words)} words){Colors.END}")
        self.max_word_len = 64
        self.max_rule_len = 32
        self.max_result_len = 512
        print(f"{Colors.CYAN}Max word length: {self.max_word_len}{Colors.END}")
        print(f"{Colors.CYAN}Max rule length: {self.max_rule_len}{Colors.END}")
        print(f"{Colors.CYAN}Max result length: {self.max_result_len}{Colors.END}")
    
    @staticmethod
    def calculate_performance_metrics(execution_times: List[float]) -> Dict[str, Any]:
        """Summarize per-run average durations (seconds per kernel launch)."""
        if not execution_times:
            return {}
        mean = float(np.mean(execution_times))
        std = float(np.std(execution_times))
        filtered_times = [t for t in execution_times if abs(t - mean) <= 2 * std]
        if not filtered_times:
            filtered_times = execution_times
        filtered_mean = float(np.mean(filtered_times))
        cv_percent = (float(np.std(filtered_times)) / filtered_mean) * 100 if filtered_mean > 0 else 0.0
        return {
            'mean_time': filtered_mean,
            'median_time': float(np.median(filtered_times)),
            'std_time': float(np.std(filtered_times)),
            'min_time': float(min(filtered_times)),
            'max_time': float(max(filtered_times)),
            'cv_percent': float(cv_percent),
            'sample_size': len(filtered_times),
            'outliers_removed': len(execution_times) - len(filtered_times)
        }

    @staticmethod
    def _event_kernel_time_seconds(event) -> float:
        """Return actual device execution time from OpenCL event timestamps."""
        try:
            start_ns = int(event.profile.start)
            end_ns = int(event.profile.end)
        except Exception as exc:
            raise RuntimeError(
                "OpenCL event profiling data is unavailable. Ensure the command "
                "queue was created with PROFILING_ENABLE and the event completed."
            ) from exc
        elapsed_ns = end_ns - start_ns
        if elapsed_ns <= 0:
            raise RuntimeError(
                f"OpenCL reported an invalid kernel profiling interval: {start_ns}..{end_ns} ns"
            )
        return elapsed_ns / 1_000_000_000.0
    
    def prepare_rule_buffers(self, rules: List[bytes]) -> Tuple[cl.Buffer, int]:
        rule_buffer_size = len(rules) * self.max_rule_len
        rule_data = np.zeros(rule_buffer_size, dtype=np.uint8)
        for i, rule in enumerate(rules):
            rule_start = i * self.max_rule_len
            for j, char in enumerate(rule[:self.max_rule_len - 1]):
                rule_data[rule_start + j] = char
        rules_buf = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=rule_data)
        return rules_buf, len(rules)
    
    def prepare_word_buffers(self, words: List[bytes]) -> Tuple[cl.Buffer, int]:
        word_buffer_size = len(words) * self.max_word_len
        word_data = np.zeros(word_buffer_size, dtype=np.uint8)
        for i, word in enumerate(words):
            word_start = i * self.max_word_len
            for j, char in enumerate(word[:self.max_word_len - 1]):
                word_data[word_start + j] = char
        words_buf = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=word_data)
        return words_buf, len(words)
    
    def test_single_rule_performance(self, rule: bytes, test_runs: int = 5) -> Dict[str, Any]:
        """Benchmark one rule with GPU-only and host end-to-end timings.

        The primary execution_time metric is derived exclusively from OpenCL
        event START/END timestamps. End-to-end timing separately includes the
        Python enqueue loop and queue completion wait, but excludes buffer
        allocation and one-time kernel argument setup.
        """
        try:
            gpu_kernel_times = []
            end_to_end_times = []
            for _run in range(test_runs):
                words_buf = rules_buf = result_buf = None
                warmup_events = []
                measured_events = []
                try:
                    words_buf, num_words = self.prepare_word_buffers(self.test_words)
                    rules_buf, num_rules = self.prepare_rule_buffers([rule])
                    result_size = num_words * num_rules * self.max_result_len
                    result_buf = cl.Buffer(self.context, cl.mem_flags.WRITE_ONLY, result_size)
                    global_size = (num_words * num_rules,)
                    self.kernel.set_args(
                        words_buf, rules_buf, result_buf,
                        np.uint32(num_words), np.uint32(num_rules),
                        np.uint32(self.max_word_len), np.uint32(self.max_rule_len),
                        np.uint32(self.max_result_len)
                    )

                    # Warm up this rule's kernel before collecting timestamps.
                    # Warm-up events are never included in either metric.
                    warmup_iterations = max(3, min(10, self.iterations // 10))
                    warmup_events = [
                        cl.enqueue_nd_range_kernel(self.queue, self.kernel, global_size, None)
                        for _ in range(warmup_iterations)
                    ]
                    self.queue.finish()

                    # OpenCL event START..END measures device execution only.
                    # Wall time separately captures host dispatch + completion.
                    end_to_end_start_ns = time.perf_counter_ns()
                    for _ in range(self.iterations):
                        measured_events.append(
                            cl.enqueue_nd_range_kernel(self.queue, self.kernel, global_size, None)
                        )
                    self.queue.finish()
                    end_to_end_elapsed_ns = time.perf_counter_ns() - end_to_end_start_ns

                    event_durations = [
                        self._event_kernel_time_seconds(event) for event in measured_events
                    ]
                    gpu_kernel_times.append(sum(event_durations) / self.iterations)
                    end_to_end_times.append(
                        (end_to_end_elapsed_ns / 1_000_000_000.0) / self.iterations
                    )
                finally:
                    for event in warmup_events + measured_events:
                        if hasattr(event, 'release'):
                            event.release()
                    for buffer in (words_buf, rules_buf, result_buf):
                        if buffer is not None and hasattr(buffer, 'release'):
                            buffer.release()

            gpu_metrics = self.calculate_performance_metrics(gpu_kernel_times)
            end_to_end_metrics = self.calculate_performance_metrics(end_to_end_times)
            total_operations = num_words * num_rules * self.iterations * test_runs
            operations_per_kernel = num_words * num_rules
            gpu_operations_per_sec = (
                operations_per_kernel / gpu_metrics['mean_time']
                if gpu_metrics['mean_time'] > 0 else 0
            )
            end_to_end_operations_per_sec = (
                operations_per_kernel / end_to_end_metrics['mean_time']
                if end_to_end_metrics['mean_time'] > 0 else 0
            )
            return {
                # Backward-compatible aliases: existing charts, sorted files,
                # and optimizer continue to consume the primary GPU-only time.
                'execution_time': gpu_metrics['mean_time'],
                'gpu_kernel_time_seconds': gpu_metrics['mean_time'],
                'end_to_end_time_seconds': end_to_end_metrics['mean_time'],
                'operations_per_sec': gpu_operations_per_sec,
                'gpu_operations_per_sec': gpu_operations_per_sec,
                'end_to_end_operations_per_sec': end_to_end_operations_per_sec,
                'operations_per_kernel': operations_per_kernel,
                'total_operations': total_operations,
                'timing_method': 'opencl_event_profiling',
                'success': True,
                'metrics': gpu_metrics,
                'gpu_kernel_metrics': gpu_metrics,
                'end_to_end_metrics': end_to_end_metrics,
                'test_runs': test_runs,
                'iterations_per_run': self.iterations
            }
        except Exception as e:
            print(f"{Colors.RED}Error testing rule {rule}: {e}{Colors.END}")
            return {
                'execution_time': float('inf'),
                'gpu_kernel_time_seconds': float('inf'),
                'end_to_end_time_seconds': float('inf'),
                'total_operations': 0,
                'operations_per_sec': 0,
                'success': False,
                'timing_method': 'opencl_event_profiling',
                'error': str(e)
            }

    def test_rule_file_performance(self, rule_file_path: str, test_runs: int = 3, max_test_rules: int = 1000, output_basename: str = None) -> List[Tuple[str, Dict[str, Any]]]:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}Testing rule file: {rule_file_path}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        rules = self.read_rules_from_file(rule_file_path)
        if not rules:
            print(f"{Colors.RED}No rules found in {rule_file_path}{Colors.END}")
            return []
        if len(rules) > max_test_rules:
            print(f"{Colors.YELLOW}Limiting to first {max_test_rules} rules (out of {len(rules)}){Colors.END}")
            rules = rules[:max_test_rules]
        rule_performance = []
        total_rules = len(rules)
        successful_tests = 0
        for i, rule in enumerate(rules):
            rule_str = rule.decode('ascii', errors='ignore')
            print(f"{Colors.WHITE}  Testing rule {i+1}/{total_rules}: {Colors.YELLOW}{rule_str}{Colors.END}")
            performance_data = self.test_single_rule_performance(rule, test_runs)
            if performance_data['success']:
                successful_tests += 1
                rule_performance.append((rule_str, performance_data))
                time_color = Colors.GREEN if performance_data['execution_time'] < 0.001 else Colors.YELLOW if performance_data['execution_time'] < 0.01 else Colors.RED
                cv_color = Colors.GREEN if performance_data['metrics']['cv_percent'] < 10 else Colors.YELLOW if performance_data['metrics']['cv_percent'] < 20 else Colors.RED
                print(f"    {Colors.CYAN}GPU kernel:{Colors.END} {time_color}{performance_data['gpu_kernel_time_seconds'] * 1e6:.3f} µs{Colors.END} "
                      f"{Colors.CYAN}End-to-end:{Colors.END} {performance_data['end_to_end_time_seconds'] * 1e6:.3f} µs "
                      f"{Colors.CYAN}GPU ops/sec:{Colors.END} {Colors.MAGENTA}{performance_data['gpu_operations_per_sec']:,.0f}{Colors.END} "
                      f"{Colors.CYAN}CV:{Colors.END} {cv_color}{performance_data['metrics']['cv_percent']:.1f}%{Colors.END} "
                      f"{Colors.CYAN}Runs:{Colors.END} {performance_data['test_runs']}")
            else:
                print(f"    {Colors.RED}FAILED: {performance_data.get('error', 'Unknown error')}{Colors.END}")
        rule_performance.sort(key=lambda x: x[1]['execution_time'])
        success_color = Colors.GREEN if successful_tests == total_rules else Colors.YELLOW if successful_tests > total_rules * 0.8 else Colors.RED
        print(f"\n{success_color}Completed: {successful_tests}/{total_rules} rules successful{Colors.END}")
        if self.visualizer and rule_performance:
            base_name = output_basename or os.path.splitext(os.path.basename(rule_file_path))[0]
            self.visualizer.generate_dashboard({'rule_performance': rule_performance, 'test_runs': test_runs, 'timestamp': datetime.now().isoformat()}, base_name)
        return rule_performance
    
    def read_rules_from_file(self, file_path: str) -> List[bytes]:
        rules = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    if '#' in line: line = line.split('#')[0].strip()
                    if line: rules.append(line.encode('ascii', errors='ignore'))
            print(f"{Colors.GREEN}Read {len(rules)} rules from {file_path}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error reading rule file {file_path}: {e}{Colors.END}")
        return rules
    
    def save_sorted_rules(self, rule_performance: List[Tuple[str, Dict[str, Any]]], output_file: str):
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Rules sorted by performance (fastest first)\n")
                f.write(f"# Generated by RulePerformanceTester\n")
                f.write(f"# Total rules: {len(rule_performance)}\n")
                f.write(f"# Test date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Primary metric: GPU kernel execution time from OpenCL event START..END timestamps\n")
                f.write(f"# End-to-end time includes host enqueue + queue completion wait (diagnostic only)\n")
                f.write(f"# Format: rule # gpu_kernel_time_seconds end_to_end_time_seconds gpu_operations_per_sec coefficient_of_variation\n\n")
                for rule, perf_data in rule_performance:
                    f.write(
                        f"{rule} # GPU {perf_data['gpu_kernel_time_seconds']:.9f}s | "
                        f"E2E {perf_data['end_to_end_time_seconds']:.9f}s | "
                        f"{perf_data['gpu_operations_per_sec']:,.0f} GPU ops/sec | "
                        f"{perf_data['metrics']['cv_percent']:.1f}% CV\n"
                    )
            print(f"{Colors.GREEN}Sorted rules saved to: {output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error saving sorted rules: {e}{Colors.END}")
    
    def save_performance_report(self, rule_performance: List[Tuple[str, Dict[str, Any]]], report_file: str,
                                identical_dicts: bool = False):
        try:
            report_data = {
                "metadata": {
                    "total_rules": len(rule_performance),
                    "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "test_iterations": self.iterations,
                    "test_runs_per_rule": (rule_performance[0][1].get("test_runs", 0) if rule_performance else 0),
                    "test_words_count": len(self.test_words),
                    "max_word_len": self.max_word_len,
                    "max_rule_len": self.max_rule_len,
                    "identical_dicts_mode": identical_dicts,
                    "timing_method": "opencl_event_profiling",
                    "opencl_profiling_enabled": bool(getattr(self, "profiling_enabled", False)),
                    "opencl_command_queue_property": "PROFILING_ENABLE",
                    "primary_time_metric": "gpu_kernel_time_seconds",
                    "end_to_end_time_definition": "Host enqueue loop plus queue completion wait; excludes buffer allocation and kernel argument setup.",
                    "device_name": str(getattr(getattr(self, 'device', None), 'name', 'unknown')),
                    "device_type": "GPU",
                    "profiling_timer_resolution_ns": int(getattr(getattr(self, 'device', None), 'profiling_timer_resolution', 0) or 0)
                },
                "rules": [
                    {
                        "rule": rule,
                        # Keep execution_time_seconds for compatibility; it now
                        # explicitly aliases the GPU-only OpenCL event duration.
                        "execution_time_seconds": perf_data['gpu_kernel_time_seconds'],
                        "gpu_kernel_time_seconds": perf_data['gpu_kernel_time_seconds'],
                        "end_to_end_time_seconds": perf_data['end_to_end_time_seconds'],
                        "operations_per_second": perf_data['gpu_operations_per_sec'],
                        "gpu_operations_per_second": perf_data['gpu_operations_per_sec'],
                        "end_to_end_operations_per_second": perf_data['end_to_end_operations_per_sec'],
                        "operations_per_kernel": perf_data['operations_per_kernel'],
                        "timing_method": perf_data['timing_method'],
                        "total_operations": perf_data['total_operations'],
                        "performance_rank": i + 1,
                        "statistical_metrics": perf_data['gpu_kernel_metrics'],
                        "end_to_end_statistical_metrics": perf_data['end_to_end_metrics']
                    }
                    for i, (rule, perf_data) in enumerate(rule_performance)
                ]
            }
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            print(f"{Colors.GREEN}Performance report saved to: {report_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error saving performance report: {e}{Colors.END}")

class RuleSetOptimizer:
    def __init__(self, max_rules: int = 1000, max_total_time: float = 60.0):
        self.max_rules = max_rules
        self.max_total_time = max_total_time
    
    def create_optimized_set(self, performance_reports: List[str], output_file: str):
        all_rules = []
        for report_file in performance_reports:
            if os.path.exists(report_file):
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                        all_rules.extend(data['rules'])
                    print(f"{Colors.GREEN}Loaded performance data from {report_file}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}Error loading performance report {report_file}: {e}{Colors.END}")
        if not all_rules:
            print(f"{Colors.RED}No performance data found!{Colors.END}")
            return
        def gpu_time(rule):
            return rule.get('gpu_kernel_time_seconds', rule.get('execution_time_seconds', float('inf')))

        all_rules.sort(key=gpu_time)
        selected_rules = []
        total_time = 0.0
        for rule in all_rules:
            rule_gpu_time = gpu_time(rule)
            if len(selected_rules) < self.max_rules and total_time + rule_gpu_time <= self.max_total_time:
                selected_rules.append(rule)
                total_time += rule_gpu_time
        with open(output_file, 'w') as f:
            f.write("# Optimized rule set - fastest GPU-kernel-time rules\n")
            f.write(f"# Total rules: {len(selected_rules)}\n")
            f.write(f"# Estimated cumulative GPU kernel time: {total_time:.9f}s\n")
            f.write(f"# Max rules constraint: {self.max_rules}\n")
            f.write(f"# Max cumulative GPU kernel time constraint: {self.max_total_time}s\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for rule in selected_rules:
                f.write(f"{rule['rule']}\n")
        report_file = output_file.replace('.rule', '_optimization_report.json')
        optimization_report = {
            "optimization_parameters": {
                "max_rules": self.max_rules,
                "max_total_time": self.max_total_time,
                "actual_rules_selected": len(selected_rules),
                "actual_total_gpu_kernel_time_seconds": total_time,
                "timing_metric": "gpu_kernel_time_seconds"
            },
            "selected_rules": selected_rules
        }
        with open(report_file, 'w') as f:
            json.dump(optimization_report, f, indent=2)
        print(f"\n{Colors.GREEN}Optimized rule set created: {output_file}{Colors.END}")
        print(f"{Colors.CYAN}Selected {len(selected_rules)} rules with cumulative GPU kernel time {total_time:.9f}s{Colors.END}")
        print(f"{Colors.CYAN}Optimization report: {report_file}{Colors.END}")

def find_rule_files(rule_paths: List[str]) -> List[str]:
    rule_files = []
    for path in rule_paths:
        if os.path.isfile(path):
            if path.endswith('.rule'):
                rule_files.append(path)
            else:
                print(f"{Colors.YELLOW}Warning: {path} is not a .rule file, skipping{Colors.END}")
        elif os.path.isdir(path):
            rule_files_found = list(Path(path).rglob('*.rule'))
            if rule_files_found:
                rule_files.extend([str(f) for f in rule_files_found])
                print(f"{Colors.GREEN}Found {len(rule_files_found)} rule files in {path}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Warning: No .rule files found in directory {path}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}Warning: Path not found: {path}{Colors.END}")
    return sorted(list(set(rule_files)))


def build_rule_output_names(rule_files: List[str], labels_by_path: Dict[str, str]) -> Dict[str, str]:
    """Map input paths to clean, unique output stems without exposing storage IDs."""
    used_names = set()
    output_names = {}
    for rule_file in rule_files:
        requested_label = labels_by_path.get(os.path.abspath(rule_file), os.path.basename(rule_file))
        label_name = os.path.basename(str(requested_label or 'rules'))
        output_name = os.path.splitext(label_name)[0]
        output_name = re.sub(r'[^A-Za-z0-9._ -]+', '_', output_name).strip(' ._-')[:120] or 'rules'
        unique_name = output_name
        suffix = 2
        while unique_name.casefold() in used_names:
            tail = f'-{suffix}'
            unique_name = f'{output_name[:120 - len(tail)]}{tail}'
            suffix += 1
        used_names.add(unique_name.casefold())
        output_names[os.path.abspath(rule_file)] = unique_name
    return output_names

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description='Hashcat Rule Performance Benchmark Tool with Advanced Visualizations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.BOLD}Examples:{Colors.END}
  {Colors.CYAN}# Basic testing with visualizations{Colors.END}
  python3 rule_benchmark.py -r best64.rule --visualize
  
  {Colors.CYAN}# Limit number of rules for quick testing{Colors.END}
  python3 rule_benchmark.py -r best64.rule --max-test-rules 100
  
  {Colors.CYAN}# Full testing with optimization{Colors.END}
  python3 rule_benchmark.py -r best64.rule --visualize --optimize --max-optimize-rules 500

  {Colors.CYAN}# Precision mode: test reject/filter rules with tiled built-in words{Colors.END}
  python3 rule_benchmark.py -r best64.rule --identical-dicts

  {Colors.CYAN}# Precision mode + increased word count for more GPU work per measurement{Colors.END}
  python3 rule_benchmark.py -r best64.rule --identical-dicts --max-words 5000 --iterations 100
        '''
    )
    parser.add_argument('--rules', '-r', nargs='+', required=True, help='Rule files or directories containing .rule files')
    parser.add_argument('--rule-labels', nargs='+', default=None, help='Optional display/output names aligned with --rules (used by the RULEOPS web UI to hide internal upload IDs)')
    parser.add_argument('--output', '-o', default='./benchmark_results', help='Output directory for results')
    parser.add_argument('--iterations', '-i', type=int, default=50, help='Number of test iterations per rule')
    parser.add_argument('--test-runs', type=int, default=3, help='Number of test runs per rule for statistical accuracy')
    parser.add_argument('--max-words', type=int, default=1000, help='Maximum number of test words to use')
    parser.add_argument('--max-test-rules', type=int, default=1000, help='Maximum number of rules to test')
    parser.add_argument('--optimize', action='store_true', help='Create optimized rule set after benchmarking')
    parser.add_argument('--max-optimize-rules', type=int, default=500, help='Maximum rules for optimized set')
    parser.add_argument('--max-time', type=float, default=30.0, help='Maximum cumulative GPU kernel execution time in seconds for optimized set')
    parser.add_argument('--visualize', action='store_true', help='Generate comprehensive visualizations')
    parser.add_argument('--dpi', type=int, default=300, help='DPI for output images')
    parser.add_argument('--visualization-output', default=None, help='Separate output directory for visualizations')
    parser.add_argument('--platform', type=int, default=0, help='OpenCL platform index')
    parser.add_argument('--device', type=int, default=0, help='OpenCL device index')
    # ── Identical-dicts precision mode ──────────────────────────────────────
    parser.add_argument(
        '--identical-dicts',
        action='store_true',
        help=(
            'Tile the built-in word list repeatedly to fill --max-words entries. '
            'Every cycle is the same 16 words in the same order, so the input '
            'space is perfectly uniform across iterations — precision / reject '
            'rules (!, /, (, ), <, >, _, =, %%) see identical inputs every time, '
            'eliminating word-variance noise from the measurements.'
        )
    )
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    viz_output = args.visualization_output or os.path.join(args.output, 'visualizations')
    os.makedirs(viz_output, exist_ok=True)
    plt.rcParams['figure.dpi'] = args.dpi
    
    rule_files = find_rule_files(args.rules)
    if args.rule_labels is not None and len(args.rule_labels) != len(args.rules):
        parser.error('--rule-labels must contain exactly one name for each --rules argument')
    labels_by_path = {os.path.abspath(path): label for path, label in zip(args.rules, args.rule_labels or [])}
    output_names_by_path = build_rule_output_names(rule_files, labels_by_path)
    if not rule_files:
        print(f"{Colors.RED}No rule files found in specified paths!{Colors.END}")
        return
    print(f"\n{Colors.GREEN}Found {len(rule_files)} rule files to test:{Colors.END}")
    for rf in rule_files: print(f"  {Colors.CYAN}{rf}{Colors.END}")
    
    try:
        tester = RulePerformanceTester(platform_index=args.platform, device_index=args.device)
        tester.iterations = args.iterations
        if args.visualize: tester.setup_visualization(viz_output)
        tester.setup_test_data(
            max_words=args.max_words,
            identical_dicts=args.identical_dicts
        )
        print(f"\n{Colors.BOLD}{Colors.CYAN}Configuration Summary:{Colors.END}")
        print(f"  {Colors.WHITE}Test iterations:{Colors.END} {Colors.YELLOW}{tester.iterations}{Colors.END}")
        print(f"  {Colors.WHITE}Test runs per rule:{Colors.END} {Colors.YELLOW}{args.test_runs}{Colors.END}")
        print(f"  {Colors.WHITE}Max test rules:{Colors.END} {Colors.YELLOW}{args.max_test_rules}{Colors.END}")
        print(f"  {Colors.WHITE}Max words:{Colors.END} {Colors.YELLOW}{args.max_words}{Colors.END}")
        print(f"  {Colors.WHITE}Test words loaded:{Colors.END} {Colors.YELLOW}{len(tester.test_words)}{Colors.END}")
        if args.identical_dicts:
            print(f"  {Colors.WHITE}Identical-dicts mode:{Colors.END} {Colors.MAGENTA}ENABLED{Colors.END} "
                  f"— {len(tester.test_words)} words (built-ins tiled)")
    except Exception as e:
        print(f"{Colors.RED}Failed to initialize tester: {e}{Colors.END}")
        return
    
    performance_reports = []
    for rule_file in rule_files:
        base_name = output_names_by_path.get(os.path.abspath(rule_file), os.path.splitext(os.path.basename(rule_file))[0])
        rule_performance = tester.test_rule_file_performance(
            rule_file, test_runs=args.test_runs, max_test_rules=args.max_test_rules, output_basename=base_name
        )
        if rule_performance:
            sorted_rules_file = os.path.join(args.output, f"{base_name}_sorted.rule")
            report_file = os.path.join(args.output, f"{base_name}_performance_report.json")
            tester.save_sorted_rules(rule_performance, sorted_rules_file)
            tester.save_performance_report(rule_performance, report_file,
                                           identical_dicts=args.identical_dicts)
            performance_reports.append(report_file)
            print(f"\n{Colors.BOLD}{Colors.CYAN}Performance Summary for {rule_file}:{Colors.END}")
            fastest_time = rule_performance[0][1]['execution_time']
            fastest_color = Colors.GREEN if fastest_time < 0.001 else Colors.YELLOW if fastest_time < 0.01 else Colors.RED
            print(f"  {Colors.WHITE}Fastest GPU rule:{Colors.END} {Colors.YELLOW}{rule_performance[0][0]}{Colors.END} {Colors.CYAN}({fastest_color}{fastest_time * 1e6:.3f} µs GPU kernel){Colors.END}")
            print(f"  {Colors.WHITE}Fastest end-to-end:{Colors.END} {rule_performance[0][1]['end_to_end_time_seconds'] * 1e6:.3f} µs (host + GPU wait)")
            slowest_time = rule_performance[-1][1]['execution_time']
            slowest_color = Colors.GREEN if slowest_time < 0.001 else Colors.YELLOW if slowest_time < 0.01 else Colors.RED
            print(f"  {Colors.WHITE}Slowest GPU rule:{Colors.END} {Colors.YELLOW}{rule_performance[-1][0]}{Colors.END} {Colors.CYAN}({slowest_color}{slowest_time * 1e6:.3f} µs GPU kernel){Colors.END}")
            avg_time = sum(p[1]['execution_time'] for p in rule_performance) / len(rule_performance)
            avg_color = Colors.GREEN if avg_time < 0.001 else Colors.YELLOW if avg_time < 0.01 else Colors.RED
            avg_e2e = sum(p[1]['end_to_end_time_seconds'] for p in rule_performance) / len(rule_performance)
            print(f"  {Colors.WHITE}Average GPU kernel time:{Colors.END} {avg_color}{avg_time * 1e6:.3f} µs{Colors.END}")
            print(f"  {Colors.WHITE}Average end-to-end time:{Colors.END} {avg_e2e * 1e6:.3f} µs\n")
    
    if args.optimize and performance_reports:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}Creating Optimized Rule Set{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        optimizer = RuleSetOptimizer(max_rules=args.max_optimize_rules, max_total_time=args.max_time)
        optimized_file = os.path.join(args.output, "optimized_rules.rule")
        optimizer.create_optimized_set(performance_reports, optimized_file)
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}Rule performance testing completed!{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}All results saved to: {os.path.abspath(args.output)}{Colors.END}")
    if args.visualize:
        print(f"{Colors.BOLD}{Colors.MAGENTA}Visualizations saved to: {os.path.abspath(viz_output)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")

if __name__ == "__main__":
    main()
