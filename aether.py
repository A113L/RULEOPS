#!/usr/bin/env python3
"""
Aether Hashcat Rule Performance Benchmark Tool.
The preflight validator admits Hashcat -r rules that the OpenCL interpreter
implements faithfully, including supported multi-command chains and Hashcat 8.0 operators.
"""
from __future__ import annotations

import pyopencl as cl
import numpy as np
import time
import os
import json
import argparse
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Tuple, Any
import sys
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime

from aether_validation import validate_rule_file, validate_rule_records, write_validation_artifacts

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
# AETHER OPENCL RULE BENCHMARK KERNEL (sequential Hashcat rule interpreter)
# ============================================================================
OPENCL_KERNEL_SOURCE = r"""
#define MAX_WORD_LEN 256
#define MAX_RULE_LEN 256
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
uchar shift_case_mask(uchar c) {
    switch (c) {
        case '!': return 16; case '"': return 5; case '#': return 16;
        case '$': return 16; case '%': return 16; case '&': return 17;
        case 39: return 5; case '(': return 17; case ')': return 25;
        case '*': return 18; case '+': return 22; case ',': return 16;
        case '-': return 114; case '.': return 16; case '/': return 16;
        case '0': return 25; case '1': return 16; case '2': return 114;
        case '3': return 16; case '4': return 16; case '5': return 16;
        case '6': return 104; case '7': return 17; case '8': return 18;
        case '9': return 17; case ':': return 1; case ';': return 1;
        case '<': return 16; case '=': return 22; case '>': return 16;
        case '?': return 16; case '@': return 114;
        case '^': return 104; case '_': return 114; case '`': return 30;
        case '~': return 30;
        default: break;
    }
    if ((c >= 'A' && c <= ']') || (c >= 'a' && c <= '}')) return 32;
    return 0;
}
uchar shift_case(uchar c) { return c ^ shift_case_mask(c); }
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

unsigned int char_to_pos(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return 0xFFFFFFFF;
}
// Return 0 on success, -2 on output-length overflow.
static int duplicate_front(const unsigned char* in, int in_len,
                           unsigned char* out, int* out_len, int* changed, int n) {
    if (n > in_len) n = in_len;
    int new_len = in_len + n;
    if (new_len > MAX_OUTPUT_LEN) return -2;
    for (int i = 0; i < n; i++) out[i] = in[i];
    for (int i = 0; i < in_len; i++) out[n + i] = in[i];
    *out_len = new_len; *changed = 1;
    return 0;
}
static int duplicate_back(const unsigned char* in, int in_len,
                          unsigned char* out, int* out_len, int* changed, int n) {
    if (n > in_len) n = in_len;
    int new_len = in_len + n;
    if (new_len > MAX_OUTPUT_LEN) return -2;
    for (int i = 0; i < in_len; i++) out[i] = in[i];
    for (int i = 0; i < n; i++) out[in_len + i] = in[in_len - n + i];
    *out_len = new_len; *changed = 1;
    return 0;
}
static int duplicate_word(const unsigned char* in, int in_len,
                          unsigned char* out, int* out_len, int* changed, int times) {
    int new_len = in_len * (times + 1);
    if (new_len > MAX_OUTPUT_LEN) return -2;
    for (int rep = 0; rep <= times; rep++)
        for (int i = 0; i < in_len; i++) out[rep * in_len + i] = in[i];
    *out_len = new_len; *changed = 1;
    return 0;
}
static void rotate_left(const unsigned char* in, int in_len,
                        unsigned char* out, int* out_len, int* changed, int n) {
    if (in_len <= 0) { *out_len = 0; *changed = 0; return; }
    if (n <= 0) n = 1;
    n %= in_len;
    *out_len = in_len;
    if (n == 0) { for (int i = 0; i < in_len; i++) out[i] = in[i]; *changed = 0; return; }
    for (int i = 0; i < in_len; i++) out[i] = in[(i + n) % in_len];
    *changed = 1;
}
static void rotate_right(const unsigned char* in, int in_len,
                         unsigned char* out, int* out_len, int* changed, int n) {
    if (in_len <= 0) { *out_len = 0; *changed = 0; return; }
    if (n <= 0) n = 1;
    n %= in_len;
    *out_len = in_len;
    if (n == 0) { for (int i = 0; i < in_len; i++) out[i] = in[i]; *changed = 0; return; }
    for (int i = 0; i < in_len; i++) out[i] = in[(i - n + in_len) % in_len];
    *changed = 1;
}
static int apply_single_command(const unsigned char* in, int in_len,
                                unsigned char* out, int* out_len,
                                const unsigned char* cmd, int cmd_len) {
    int changed = 0;
    *out_len = 0;
    if (cmd_len == 1) {
        switch (cmd[0]) {
            case 'l': *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=to_lower(in[i]); changed=1; break;
            case 'u': *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=to_upper(in[i]); changed=1; break;
            case 'c': *out_len = in_len; if (in_len>0) out[0]=to_upper(in[0]); for (int i=1;i<in_len;i++) out[i]=to_lower(in[i]); changed=1; break;
            case 'C': *out_len = in_len; if (in_len>0) out[0]=to_lower(in[0]); for (int i=1;i<in_len;i++) out[i]=to_upper(in[i]); changed=1; break;
            case 't': *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=toggle_case(in[i]); changed=1; break;
            case 'h':
            case 'H': {
                const unsigned char hex_lower[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
                const unsigned char hex_upper[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
                if (in_len * 2 > MAX_OUTPUT_LEN) return -2;
                *out_len = in_len * 2;
                for (int i = 0; i < in_len; i++) {
                    out[i * 2] = (cmd[0] == 'h') ? hex_lower[in[i] >> 4] : hex_upper[in[i] >> 4];
                    out[i * 2 + 1] = (cmd[0] == 'h') ? hex_lower[in[i] & 15] : hex_upper[in[i] & 15];
                }
                changed = 1;
                break;
            }
            case 'S': *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=shift_case(in[i]); changed=1; break;
            case 'r': *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=in[in_len-1-i]; changed=1; break;
            case 'd': if (in_len*2>MAX_OUTPUT_LEN) return -2; *out_len=in_len*2; for(int i=0;i<in_len;i++){out[i]=in[i];out[in_len+i]=in[i];} changed=1; break;
            case 'f': if (in_len*2>MAX_OUTPUT_LEN) return -2; *out_len=in_len*2; for(int i=0;i<in_len;i++){out[i]=in[i];out[in_len+i]=in[in_len-1-i];} changed=1; break;
            case 'k': *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; if(in_len>=2){out[0]=in[1];out[1]=in[0];changed=1;} break;
            case 'K': *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; if(in_len>=2){out[in_len-2]=in[in_len-1];out[in_len-1]=in[in_len-2];changed=1;} break;
            case ':': *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; changed=0; break;
            case 'q': if (in_len*2>MAX_OUTPUT_LEN) return -2; int idx=0; for(int i=0;i<in_len;i++){out[idx++]=in[i];out[idx++]=in[i];} *out_len=in_len*2; changed=1; break;
            case 'E': { *out_len=in_len; int cap=1; for(int i=0;i<in_len;i++){ if(cap&&is_lower(in[i])) out[i]=to_upper(in[i]); else out[i]=to_lower(in[i]); cap=(in[i]==' '||in[i]=='-'||in[i]=='_'); } changed=1; } break;
            case '{': rotate_left(in,in_len,out,out_len,&changed,1); break;
            case '}': rotate_right(in,in_len,out,out_len,&changed,1); break;
            case '[': if (in_len>1) { *out_len=in_len-1; for(int i=1;i<in_len;i++) out[i-1]=in[i]; changed=1; } break;
            case ']': if (in_len>1) { *out_len=in_len-1; for(int i=0;i<in_len-1;i++) out[i]=in[i]; changed=1; } break;
            default: *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; changed=0; break;
        }
        return changed;
    }
    if (cmd_len == 2) {
        unsigned char cmd_char = cmd[0];
        unsigned char arg = cmd[1];
        int n = (int)char_to_pos(arg);
        if (n == 0xFFFFFFFF) n = -1;
        switch (cmd_char) {
            case 'T': if (n>=0&&n<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n]=toggle_case(in[n]); changed=1; } break;
            case 'D': if (n>=0&&n<in_len){ *out_len=in_len-1; for(int i=0;i<n;i++) out[i]=in[i]; for(int i=n+1;i<in_len;i++) out[i-1]=in[i]; changed=1; } break;
            case 'L': if (n>=0&&n<in_len){ *out_len=in_len-n; for(int i=n;i<in_len;i++) out[i-n]=in[i]; changed=1; } break;
            case 'R': if (n>=0&&n<in_len){ *out_len=n+1; for(int i=0;i<=n;i++) out[i]=in[i]; changed=1; } break;
            case '+': if (n>=0&&n<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n]=in[n]+1; changed=1; } break;
            case '-': if (n>=0&&n<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n]=in[n]-1; changed=1; } break;
            case '.': if (n>=0&&n<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n]=in[n]+1; changed=1; } break;
            case ',': if (n>=0&&n<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n]=in[n]-1; changed=1; } break;
            case '\'': if (n>=0&&n<in_len){ *out_len=n; for(int i=0;i<n;i++) out[i]=in[i]; changed=1; } break;
            case '^': if (in_len+1>MAX_OUTPUT_LEN) return -2; out[0]=arg; for(int i=0;i<in_len;i++) out[i+1]=in[i]; *out_len=in_len+1; changed=1; break;
            case '$': if (in_len+1>MAX_OUTPUT_LEN) return -2; for(int i=0;i<in_len;i++) out[i]=in[i]; out[in_len]=arg; *out_len=in_len+1; changed=1; break;
            case '@': *out_len=0; for(int i=0;i<in_len;i++){ if(in[i]!=arg) out[(*out_len)++]=in[i]; else changed=1; } break;
            case '!': for(int i=0;i<in_len;i++) if(in[i]==arg) return -1; *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; return 0;
            case '/': for(int i=0;i<in_len;i++) if(in[i]==arg){ *out_len=in_len; for(int j=0;j<in_len;j++) out[j]=in[j]; return 0; } return -1;
            case '(': if (in_len>0&&in[0]==arg){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; return 0; } return -1;
            case ')': if (in_len>0&&in[in_len-1]==arg){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; return 0; } return -1;
            case 'y': if (n>=0) return duplicate_front(in,in_len,out,out_len,&changed,n); break;
            case 'Y': if (n>=0) return duplicate_back(in,in_len,out,out_len,&changed,n); break;
            case 'z': if (n>0) { if (in_len+n>MAX_OUTPUT_LEN) return -2; out[0]=in[0]; for(int i=0;i<n;i++) out[i+1]=in[0]; for(int i=1;i<in_len;i++) out[n+i]=in[i]; *out_len=in_len+n; changed=1; } break;
            case 'Z': if (n>0) { if (in_len+n>MAX_OUTPUT_LEN) return -2; for(int i=0;i<in_len;i++) out[i]=in[i]; for(int i=0;i<n;i++) out[in_len+i]=in[in_len-1]; *out_len=in_len+n; changed=1; } break;
            case 'p': if (n>=0) return duplicate_word(in,in_len,out,out_len,&changed,n); break;
            case '{': if (n>=0) rotate_left(in,in_len,out,out_len,&changed,n); break;
            case '}': if (n>=0) rotate_right(in,in_len,out,out_len,&changed,n); break;
            case '[': if (n>=0&&n<in_len){ *out_len=in_len-n; for(int i=n;i<in_len;i++) out[i-n]=in[i]; changed=1; } break;
            case ']': if (n>=0&&n<in_len){ *out_len=in_len-n; for(int i=0;i<*out_len;i++) out[i]=in[i]; changed=1; } break;
            default: *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; changed=0; break;
        }
        return changed;
    }
    if (cmd_len == 3) {
        unsigned char cmd_char = cmd[0];
        unsigned char a1 = cmd[1];
        unsigned char a2 = cmd[2];
        int n1 = (int)char_to_pos(a1);
        int n2 = (int)char_to_pos(a2);
        if (n1 == (int)0xFFFFFFFF) n1 = -1;
        if (n2 == (int)0xFFFFFFFF) n2 = -1;
        switch (cmd_char) {
            case 'x': if (n1>=0&&n2>0&&n1<in_len){ int end=n1+n2; if(end>in_len) end=in_len; *out_len=end-n1; for(int i=0;i<*out_len;i++) out[i]=in[n1+i]; changed=1; } break;
            case 'O': if (n1>=0&&n2>0&&n1<in_len){ int end=n1+n2; if(end>in_len) end=in_len; int rm=end-n1; *out_len=in_len-rm; for(int i=0;i<n1;i++) out[i]=in[i]; for(int i=end;i<in_len;i++) out[i-rm]=in[i]; changed=1; } break;
            case 'i': if (n1>=0) { if (in_len+1>MAX_OUTPUT_LEN) return -2; int p=n1; if(p>in_len) p=in_len; for(int i=0;i<p;i++) out[i]=in[i]; out[p]=a2; for(int i=p;i<in_len;i++) out[i+1]=in[i]; *out_len=in_len+1; changed=1; } break;
            case 's': *out_len=in_len; for(int i=0;i<in_len;i++){ out[i]=(in[i]==a1)?a2:in[i]; if(in[i]==a1) changed=1; } break;
            case 'o': if (n1>=0&&n1<in_len){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; out[n1]=a2; changed=1; } break;
            case '*': if (n1>=0&&n2>=0&&n1<in_len&&n2<in_len&&n1!=n2){ *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; unsigned char tmp=out[n1]; out[n1]=out[n2]; out[n2]=tmp; changed=1; } break;
            case '3': if (n1>=0){ int count=0; *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; for(int i=0;i<in_len;i++){ if(in[i]==a2) count++; if(count==n1+1 && i+1<in_len){ out[i+1]=toggle_case(in[i+1]); changed=1; break; } } } break;
            case 'v': {
                if (n1 > 0 && n1 < in_len + 1) {
                    int required_len = in_len + (in_len / n1);
                    if (required_len > MAX_OUTPUT_LEN) return -2;
                    *out_len = 0;
                    for (int i = 0; i < in_len; i++) {
                        out[(*out_len)++] = in[i];
                        if ((i + 1) % n1 == 0) out[(*out_len)++] = a2;
                    }
                    changed = 1;
                } else {
                    *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=in[i];
                }
                break;
            }
            case 'B':
                *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=in[i];
                if (n1 >= 0 && n1 < in_len) { out[n1] = (unsigned char)(in[n1] + a2); changed = 1; }
                break;
            case '%': if (n1>=0){ int cnt=0; for(int i=0;i<in_len;i++) if(in[i]==a2) cnt++; if(cnt<n1) return -1; } *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; return 0;
            case '=': if (n1>=0&&n1<in_len&&in[n1]!=a2) return -1; *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; return 0;
            default: *out_len=in_len; for(int i=0;i<in_len;i++) out[i]=in[i]; changed=0; break;
        }
        return changed;
    }
    *out_len = in_len; for (int i=0;i<in_len;i++) out[i]=in[i]; return 0;
}
void apply_hashcat_rule(const unsigned char* word, int word_len,
                        const unsigned char* rule, int rule_len,
                        unsigned char* output, int* out_len, int* changed) {
    unsigned char buf0[MAX_OUTPUT_LEN];
    unsigned char buf1[MAX_OUTPUT_LEN];
    unsigned char* in_buf = (unsigned char*)word;
    int in_len = word_len;
    int final_changed = 0;
    int pos = 0;
    while (pos < rule_len) {
        unsigned char cmd_char = rule[pos];
        // Hashcat rule files commonly separate commands with whitespace.
        // Skip separators only at command boundaries: a space consumed as
        // an argument (for example, the operand in "$ ") remains intact.
        if (cmd_char == ' ' || cmd_char == '\t' || cmd_char == '\r' || cmd_char == '\n') {
            pos++;
            continue;
        }
        int cmd_len = 1;
        if (cmd_char=='s'||cmd_char=='x'||cmd_char=='O'||cmd_char=='i'||cmd_char=='o'||
            cmd_char=='*'||cmd_char=='3'||cmd_char=='v'||cmd_char=='B'||cmd_char=='%'||cmd_char=='=') {
            cmd_len = 3;
        } else if (pos+1 < rule_len && (cmd_char=='T'||cmd_char=='D'||cmd_char=='L'||cmd_char=='R'||
                    cmd_char=='+'||cmd_char=='-'||cmd_char=='.'||cmd_char==','||cmd_char=='\''||
                    cmd_char=='^'||cmd_char=='$'||cmd_char=='@'||cmd_char=='!'||cmd_char=='/'||
                    cmd_char=='('||cmd_char==')'||cmd_char=='y'||cmd_char=='Y'||cmd_char=='z'||
                    cmd_char=='Z'||cmd_char=='p'||cmd_char=='_'||cmd_char=='e')) {
            cmd_len = 2;
        }
        if (pos + cmd_len > rule_len) break;
        int out_len_local = 0;
        int result = apply_single_command(in_buf, in_len, buf0, &out_len_local, rule+pos, cmd_len);
        if (result < 0) { *out_len = 0; *changed = result; return; }
        if (result == 1) final_changed = 1;
        in_len = out_len_local;
        for (int i=0;i<in_len;i++) buf1[i]=buf0[i];
        in_buf = buf1;
        pos += cmd_len;
    }
    *out_len = in_len;
    for (int i=0;i<in_len;i++) output[i]=in_buf[i];
    *changed = final_changed;
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

    // Apply every command in the rule line in sequence. This supports normal
    // Hashcat -r rule chains as well as Hashcat 8.0 h/H/S/v/B operators.
    apply_hashcat_rule(word, word_len, rule, rule_len, output, &out_len, &changed);

    // Reserve one byte for the NUL terminator in the fixed-size result slot.
    if (changed > 0 && out_len > 0 && out_len < max_result_len && out_len <= MAX_OUTPUT_LEN) {
        for (int i = 0; i < out_len; i++) {
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
        """Render the fastest rules with their exact source commands as legend labels.

        Hashcat rule commands are literal text. In particular, '$', '^' and
        backslashes must not be interpreted by Matplotlib's MathText parser,
        and long commands must not be abbreviated because that makes distinct
        rules appear identical in the chart legend.
        """
        if not rule_performance:
            return

        top_rules = rule_performance[:20]
        rules = [self._literal_rule_command(rule) or '<empty rule>' for rule, _ in top_rules]
        times = [data.get('gpu_kernel_time_seconds', data.get('execution_time', float('inf'))) * 1_000_000
                 for _, data in top_rules]
        ops_sec = [data.get('gpu_operations_per_sec', data.get('operations_per_sec', 0.0)) / 1000
                   for _, data in top_rules]
        cv_values = [data['metrics']['cv_percent'] for _, data in top_rules]
        times_norm = self.normalize_data(times, invert=True)
        ops_norm = self.normalize_data(ops_sec)
        cv_norm = self.normalize_data(cv_values, invert=True)
        categories = ['GPU Kernel Time\n(μs)', 'GPU Throughput\n(K ops/sec)', 'Consistency\n(CV %)']

        # Reserve a dedicated right-hand area for 20 complete rule commands.
        # A wider figure keeps the full Hashcat syntax readable without clipping.
        fig, ax = plt.subplots(figsize=(20, 12), subplot_kw=dict(projection='polar'))
        angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
        angles += angles[:1]
        for rule, time_n, ops_n, cv_n in zip(rules, times_norm, ops_norm, cv_norm):
            values = [time_n, ops_n, cv_n]
            values += values[:1]
            ax.plot(angles, values, 'o-', linewidth=2, label=rule, markersize=6, alpha=0.7)
            ax.fill(angles, values, alpha=0.1)

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories)
        ax.set_ylim(0, 1)
        ax.set_yticks([])
        ax.grid(True, alpha=0.3)
        ax.set_title('Rule Performance Radar Chart\n(Top 20 Rules)', size=16, pad=20)

        legend = ax.legend(
            bbox_to_anchor=(1.06, 1.0),
            loc='upper left',
            borderaxespad=0,
            fontsize=7,
            labelspacing=0.55,
            handlelength=2.2,
            frameon=False,
        )
        # Disable MathText after creating the legend: Hashcat syntax such as
        # '$1', '^2' and '\' must remain exactly as it appears in the .rule file.
        for label in legend.get_texts():
            label.set_parse_math(False)
            label.set_fontfamily('DejaVu Sans Mono')
            label.set_fontsize(7)

        fig.subplots_adjust(left=0.02, right=0.67, top=0.92, bottom=0.05)
        output_path = os.path.join(self.output_dir, f"{filename}_radar.png")
        fig.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close(fig)
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
    def _relative_tier_specs(times_us: List[float]):
        """Return tie-preserving relative tier definitions for one rule file."""
        values = np.asarray(times_us, dtype=float)
        values = values[np.isfinite(values)]
        if values.size == 0:
            return []

        unique_values, group_counts = np.unique(values, return_counts=True)
        if unique_values.size == 1:
            value = float(unique_values[0])
            return [{
                'id': 'comparable', 'label': f'Comparable (≈{value:.3f} µs)',
                'color': '#3498db', 'min_us': value, 'max_us': value,
            }]

        cumulative = np.cumsum(group_counts)
        total = int(values.size)
        # Boundaries are placed near one-third and two-thirds of the sample,
        # but only between distinct timings so equal measurements never split.
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

        specs = [{
            'id': 'fastest',
            'label': f'Fastest (≤{unique_values[first_cut - 1]:.3f} µs)',
            'color': '#2ecc71',
            'min_us': None,
            'max_us': float(unique_values[first_cut - 1]),
        }]
        if second_cut < unique_values.size:
            specs.append({
                'id': 'middle',
                'label': f'Middle ({unique_values[first_cut]:.3f}–{unique_values[second_cut - 1]:.3f} µs)',
                'color': '#f1c40f',
                'min_us': float(unique_values[first_cut]),
                'max_us': float(unique_values[second_cut - 1]),
            })
            slow_min = float(unique_values[second_cut])
        else:
            slow_min = float(unique_values[first_cut])
        specs.append({
            'id': 'slowest', 'label': f'Slowest (≥{slow_min:.3f} µs)',
            'color': '#e74c3c', 'min_us': slow_min, 'max_us': None,
        })
        return specs

    @classmethod
    def _relative_performance_tiers(cls, times_us: List[float]):
        """Build balanced, tie-preserving counts/labels/colors for the PNG pie."""
        specs = cls._relative_tier_specs(times_us)
        values = np.asarray(times_us, dtype=float)
        values = values[np.isfinite(values)]
        counts = []
        for spec in specs:
            if spec['id'] == 'comparable':
                count = int(values.size)
            elif spec['id'] == 'fastest':
                count = int(np.count_nonzero(values <= spec['max_us']))
            elif spec['id'] == 'middle':
                count = int(np.count_nonzero((values >= spec['min_us']) & (values <= spec['max_us'])))
            else:
                count = int(np.count_nonzero(values >= spec['min_us']))
            counts.append(count)
        return counts, [spec['label'] for spec in specs], [spec['color'] for spec in specs]

    def create_interactive_report(self, rule_performance: List[Tuple[str, Dict]], filename: str,
                                  corpus_description: str = "", validation_summary: Dict[str, Any] | None = None,
                                  default_export_rule_count: int = 500):
        """Write a self-contained HTML report with interactive tier filtering/export."""
        valid_rows = []
        for rule, data in rule_performance:
            kernel_seconds = data.get('gpu_kernel_time_seconds', data.get('execution_time'))
            try:
                kernel_seconds = float(kernel_seconds)
            except (TypeError, ValueError):
                continue
            if not np.isfinite(kernel_seconds) or kernel_seconds < 0:
                continue
            metrics = data.get('gpu_kernel_metrics') or data.get('metrics') or {}
            e2e_seconds = data.get('end_to_end_time_seconds')
            try:
                e2e_us = float(e2e_seconds) * 1_000_000 if e2e_seconds is not None else None
                if e2e_us is not None and not np.isfinite(e2e_us):
                    e2e_us = None
            except (TypeError, ValueError):
                e2e_us = None
            ops_sec = data.get('gpu_operations_per_sec', data.get('operations_per_sec', 0.0))
            try:
                ops_sec = float(ops_sec)
                if not np.isfinite(ops_sec):
                    ops_sec = 0.0
            except (TypeError, ValueError):
                ops_sec = 0.0
            cv = metrics.get('cv_percent')
            try:
                cv = float(cv) if cv is not None and np.isfinite(float(cv)) else None
            except (TypeError, ValueError):
                cv = None
            valid_rows.append({
                'command': str(rule),
                'gpu_kernel_time_us': kernel_seconds * 1_000_000,
                'end_to_end_time_us': e2e_us,
                'gpu_ops_per_sec': ops_sec,
                'cv_percent': cv,
            })

        if not valid_rows:
            print(f"{Colors.YELLOW}No valid GPU timing data available for interactive report{Colors.END}")
            return

        valid_rows.sort(key=lambda row: row['gpu_kernel_time_us'])
        specs = self._relative_tier_specs([row['gpu_kernel_time_us'] for row in valid_rows])
        tiers = []
        for spec in specs:
            if spec['id'] == 'comparable':
                selected = list(valid_rows)
            elif spec['id'] == 'fastest':
                selected = [row for row in valid_rows if row['gpu_kernel_time_us'] <= spec['max_us']]
            elif spec['id'] == 'middle':
                selected = [row for row in valid_rows if spec['min_us'] <= row['gpu_kernel_time_us'] <= spec['max_us']]
            else:
                selected = [row for row in valid_rows if row['gpu_kernel_time_us'] >= spec['min_us']]
            tiers.append({
                **spec,
                'count': len(selected),
                'percent': (len(selected) / len(valid_rows)) * 100.0,
                'rules': selected,
            })

        kernel_times = [row['gpu_kernel_time_us'] for row in valid_rows]
        all_ops = [row['gpu_ops_per_sec'] for row in valid_rows]
        payload = {
            'meta': {
                'file_name': str(filename),
                'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
                'corpus_description': str(corpus_description or ''),
                'total_rules': len(valid_rows),
                'mean_gpu_kernel_time_us': float(np.mean(kernel_times)),
                'median_gpu_kernel_time_us': float(np.median(kernel_times)),
                'mean_gpu_ops_per_sec': float(np.mean(all_ops)) if all_ops else 0.0,
                'profiling_enabled': bool(getattr(self, 'profiling_enabled', True)),
                'primary_metric': 'GPU Kernel Time · OpenCL Event Profiling',
                'validation_summary': dict(validation_summary or {}),
                'default_export_rule_count': max(1, int(default_export_rule_count or 1)),
            },
            'tiers': tiers,
        }
        # Escape HTML-significant characters even though the data is inside a
        # non-executable JSON script element; this prevents a rule containing
        # </script> from terminating the data block.
        data_json = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        data_json = (data_json.replace('&', r'\u0026').replace('<', r'\u003c')
                              .replace('>', r'\u003e').replace('\u2028', r'\u2028')
                              .replace('\u2029', r'\u2029'))
        html = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aether · Interactive GPU Rule Performance</title>
<style>
:root{color-scheme:dark;--bg:#0d131b;--panel:#151e29;--panel2:#101720;--line:#2b3948;--text:#e8eef5;--muted:#93a1b2;--green:#2ecc71;--yellow:#f1c40f;--red:#e74c3c;--blue:#3498db}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1440px;margin:0 auto;padding:30px 28px 48px}.eyebrow{font:11px ui-monospace,monospace;letter-spacing:.13em;color:#9fbd83;text-transform:uppercase}
h1{font-size:clamp(25px,3vw,38px);line-height:1.15;margin:8px 0}p{color:var(--muted);margin:7px 0}.subline{font-size:13px;margin-bottom:22px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px}.stat{padding:15px}.stat small{display:block;color:var(--muted);font-size:11px}.stat b{display:block;font:600 22px ui-monospace,monospace;margin-top:7px}
.layout{display:grid;grid-template-columns:minmax(280px,390px) minmax(0,1fr);gap:16px;align-items:start}.panel{padding:18px;min-width:0}.panel h2{font-size:17px;margin:0 0 4px}.chart-wrap{display:grid;place-items:center;padding:10px 0 0}.chart{width:min(100%,330px);height:auto;overflow:visible}.slice{fill:none;stroke-width:38;cursor:pointer;pointer-events:stroke;transition:opacity .15s,stroke-width .15s}.slice:hover,.slice.active{stroke-width:46}.slice:focus{outline:none;stroke-width:48}.chart-center{font:700 24px ui-monospace,monospace;fill:var(--text);text-anchor:middle}.chart-center-label{font:11px system-ui,sans-serif;fill:var(--muted);text-anchor:middle}
.legend{display:grid;gap:8px;margin-top:12px}.tier-button{width:100%;display:grid;grid-template-columns:12px minmax(0,1fr) auto;gap:10px;align-items:center;text-align:left;padding:10px 11px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--text);cursor:pointer}.tier-button:hover,.tier-button.active{border-color:#91b66d;background:#1c2a25}.swatch{width:10px;height:10px;border-radius:50%}.tier-button strong{font-size:12px}.tier-button small{display:block;color:var(--muted);font-size:11px}.tier-count{font:12px ui-monospace,monospace;color:#dbe7d0}
.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin:14px 0}.toolbar input{flex:1;min-width:190px;background:#0c131c;border:1px solid var(--line);border-radius:7px;color:var(--text);padding:10px 12px}.export-count-control{display:flex;flex-wrap:wrap;align-items:center;gap:8px;color:var(--muted);font-size:12px}.toolbar .export-count-control input{flex:0 0 112px;width:112px;min-width:112px}.export-fastest-toolbar{margin-top:8px;margin-bottom:4px}.button{border:1px solid #547342;background:#21301f;color:#d8edc9;border-radius:7px;padding:10px 13px;font-weight:650;cursor:pointer}.button:hover{background:#2d4328}.button:disabled{opacity:.4;cursor:not-allowed}.selection-note{font-size:12px;margin:0 0 10px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;min-width:780px}th,td{padding:10px 11px;border-bottom:1px solid #293542;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#202b38;color:#aab9c9;font-size:10px;letter-spacing:.06em;text-transform:uppercase}td{font-size:12px}td.rule{width:48%;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;color:#e2eaf2}td.num{font:11px ui-monospace,monospace;white-space:nowrap}.pagination{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:12px;color:var(--muted);font-size:11px}.pagination button{border:1px solid var(--line);background:#111a24;color:var(--text);padding:7px 10px;border-radius:6px}.pagination button:disabled{opacity:.35;cursor:not-allowed}.footnote{font-size:11px;margin-top:16px}
@media(max-width:900px){main{padding:20px 14px}.layout{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:430px){.stats{grid-template-columns:1fr 1fr}.stat{padding:11px}.stat b{font-size:17px}.panel{padding:13px}}
</style>
</head>
<body><main>
<div class="eyebrow">Aether · OpenCL Event Profiling</div><h1 id="report-title">Interactive GPU Rule Performance</h1>
<p class="subline" id="report-subtitle">Click a performance tier to inspect the exact Hashcat commands measured in that group.</p>
<section class="stats" aria-label="Benchmark summary">
 <div class="stat"><small>Rules benchmarked</small><b id="total-rules">—</b></div><div class="stat"><small>Mean GPU Kernel Time</small><b id="mean-time">—</b></div><div class="stat"><small>Median GPU Kernel Time</small><b id="median-time">—</b></div><div class="stat"><small>Mean GPU throughput</small><b id="mean-throughput">—</b></div>
</section>
<div class="layout"><section class="panel"><h2>Relative GPU Performance Tiers</h2><p>Click a pie segment or category to list its rules. Equal GPU timings stay together.</p>
 <div class="chart-wrap"><svg class="chart" id="tier-chart" viewBox="0 0 220 220" role="img" aria-label="Interactive pie chart of relative GPU performance tiers"><circle cx="110" cy="110" r="76" fill="none" stroke="#273342" stroke-width="38"></circle><text x="110" y="106" class="chart-center" id="chart-total">—</text><text x="110" y="126" class="chart-center-label">rules</text></svg></div>
 <div class="legend" id="tier-legend"></div></section>
 <section class="panel"><h2 id="table-title">Rules</h2><p class="selection-note" id="selection-note"></p><div class="toolbar"><input id="rule-search" type="search" placeholder="Filter exact rule commands…" aria-label="Filter rule commands"><button class="button" id="export-tier" type="button">↓ Download category .rule</button></div>
 <div class="toolbar export-fastest-toolbar"><label class="export-count-control" for="export-count"><span>Fastest rules to download</span><input id="export-count" type="number" min="1" step="1" value="500"></label><button class="button" id="export-fastest" type="button">↓ Download fastest rules .rule</button></div><p class="selection-note" id="export-count-note"></p>
 <div class="table-wrap"><table><thead><tr><th>Exact Hashcat rule command</th><th>GPU Kernel Time</th><th>GPU ops/sec</th><th>End-to-End Time</th><th>CV</th></tr></thead><tbody id="rule-rows"></tbody></table></div>
 <div class="pagination"><span id="page-status">—</span><div><button id="previous-page" type="button">Previous</button> <button id="next-page" type="button">Next</button></div></div>
 </section></div>
<p class="footnote">Primary metric: GPU Kernel Time from OpenCL event START/END timestamps. End-to-End Time is diagnostic only. Categories are relative to this rule file; this report contains the exact source commands.</p>
</main>
<script id="report-data" type="application/json">__AETHER_REPORT_JSON__</script>
<script>
'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const $=id=>document.getElementById(id);let activeTier=report.tiers[0]||null;let page=0;const pageSize=100;
const rankedRules=report.tiers.flatMap(tier=>tier.rules).sort((a,b)=>a.gpu_kernel_time_us-b.gpu_kernel_time_us);
const fmt=(v,d=3)=>Number.isFinite(Number(v))?Number(v).toLocaleString(undefined,{minimumFractionDigits:d,maximumFractionDigits:d}):'—';
const fmtRate=v=>Number.isFinite(Number(v))?Number(v).toLocaleString(undefined,{maximumFractionDigits:0}):'—';
$('report-title').textContent=report.meta.file_name+' · GPU Rule Performance';
const validation=report.meta.validation_summary||{};const skipped=Number(validation.invalid_rules||0)+Number(validation.cli_only_rules||0)+Number(validation.unsupported_rules||0);$('report-subtitle').textContent=(report.meta.corpus_description?report.meta.corpus_description+' · ':'')+report.meta.total_rules.toLocaleString()+' benchmarkable rules · '+skipped.toLocaleString()+' skipped by preflight · generated '+report.meta.generated_at;
$('total-rules').textContent=report.meta.total_rules.toLocaleString();$('mean-time').textContent=fmt(report.meta.mean_gpu_kernel_time_us)+' µs';$('median-time').textContent=fmt(report.meta.median_gpu_kernel_time_us)+' µs';$('mean-throughput').textContent=fmtRate(report.meta.mean_gpu_ops_per_sec)+' ops/s';$('chart-total').textContent=report.meta.total_rules.toLocaleString();
const svgNS='http://www.w3.org/2000/svg';function renderPie(){const svg=$('tier-chart');svg.querySelectorAll('.slice').forEach(n=>n.remove());const total=report.meta.total_rules||1;const radius=76,circ=2*Math.PI*radius;let offset=0;report.tiers.forEach(tier=>{const length=circ*tier.count/total;const circle=document.createElementNS(svgNS,'circle');circle.setAttribute('class','slice'+(activeTier&&activeTier.id===tier.id?' active':''));circle.setAttribute('cx','110');circle.setAttribute('cy','110');circle.setAttribute('r',String(radius));circle.setAttribute('stroke',tier.color);circle.setAttribute('stroke-dasharray',`${length} ${circ-length}`);circle.setAttribute('stroke-dashoffset',String(-offset));circle.setAttribute('transform','rotate(-90 110 110)');circle.setAttribute('tabindex','0');circle.setAttribute('role','button');circle.setAttribute('aria-label',`${tier.label}: ${tier.count} rules, ${fmt(tier.percent,1)} percent`);circle.addEventListener('click',()=>selectTier(tier.id));circle.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();selectTier(tier.id)}});svg.append(circle);offset+=length;});}
function renderLegend(){const root=$('tier-legend');root.replaceChildren();report.tiers.forEach(tier=>{const b=document.createElement('button');b.type='button';b.className='tier-button'+(activeTier&&activeTier.id===tier.id?' active':'');const sw=document.createElement('span');sw.className='swatch';sw.style.background=tier.color;const copy=document.createElement('span');const strong=document.createElement('strong');strong.textContent=tier.label;const small=document.createElement('small');small.textContent=`${fmt(tier.percent,1)}% of tested rules`;copy.append(strong,small);const count=document.createElement('span');count.className='tier-count';count.textContent=tier.count.toLocaleString();b.append(sw,copy,count);b.addEventListener('click',()=>selectTier(tier.id));root.append(b);});}
function selectTier(id){activeTier=report.tiers.find(t=>t.id===id)||report.tiers[0]||null;page=0;$('rule-search').value='';renderPie();renderLegend();renderTable();}
function renderTable(){const body=$('rule-rows');body.replaceChildren();if(!activeTier){$('table-title').textContent='No rules';$('selection-note').textContent='No valid GPU timing data was recorded.';$('page-status').textContent='0 rules';$('export-tier').disabled=true;return;}const query=$('rule-search').value.trim().toLowerCase();const filtered=activeTier.rules.filter(r=>!query||r.command.toLowerCase().includes(query));const pageCount=Math.max(1,Math.ceil(filtered.length/pageSize));page=Math.max(0,Math.min(page,pageCount-1));const start=page*pageSize;filtered.slice(start,start+pageSize).forEach(rule=>{const tr=document.createElement('tr');const cmd=document.createElement('td');cmd.className='rule';cmd.textContent=rule.command;const gpu=document.createElement('td');gpu.className='num';gpu.textContent=fmt(rule.gpu_kernel_time_us)+' µs';const rate=document.createElement('td');rate.className='num';rate.textContent=fmtRate(rule.gpu_ops_per_sec);const e2e=document.createElement('td');e2e.className='num';e2e.textContent=rule.end_to_end_time_us===null?'—':fmt(rule.end_to_end_time_us)+' µs';const cv=document.createElement('td');cv.className='num';cv.textContent=rule.cv_percent===null?'—':fmt(rule.cv_percent,2)+'%';tr.append(cmd,gpu,rate,e2e,cv);body.append(tr);});$('table-title').textContent=activeTier.label+' · rules';$('selection-note').textContent=`${activeTier.count.toLocaleString()} rules in this category. Search filters the table; download exports the entire category.`;$('page-status').textContent=filtered.length?`Showing ${start+1}–${Math.min(start+pageSize,filtered.length)} of ${filtered.length.toLocaleString()} matching rules`:'No matching rules';$('previous-page').disabled=page===0;$('next-page').disabled=page>=pageCount-1;$('export-tier').disabled=!activeTier.rules.length;}
function downloadRuleFile(rules,suffix){if(!rules.length)return;const contents=rules.map(r=>r.command).join('\n')+'\n';const url=URL.createObjectURL(new Blob([contents],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;const safeBase=report.meta.file_name.replace(/[^A-Za-z0-9._-]+/g,'_')||'aether_rules';a.download=safeBase+'_'+suffix+'.rule';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('rule-search').addEventListener('input',()=>{page=0;renderTable()});$('previous-page').addEventListener('click',()=>{page--;renderTable()});$('next-page').addEventListener('click',()=>{page++;renderTable()});$('export-tier').addEventListener('click',()=>{if(activeTier)downloadRuleFile(activeTier.rules,activeTier.id);});
const exportCountInput=$('export-count');const configuredExportCount=Math.max(1,Math.floor(Number(report.meta.default_export_rule_count)||500));const availableExportCount=rankedRules.length;exportCountInput.max=String(availableExportCount);exportCountInput.value=String(Math.min(configuredExportCount,availableExportCount));$('export-fastest').disabled=availableExportCount===0;
$('export-count-note').textContent=availableExportCount?`Default from Aether settings: ${configuredExportCount.toLocaleString()} rules. ${availableExportCount.toLocaleString()} benchmarked rules are available in this report; export is limited to the available count.`:'No benchmarked rules are available to export.';
$('export-fastest').addEventListener('click',()=>{const requested=Number(exportCountInput.value);if(!Number.isSafeInteger(requested)||requested<1){$('export-count-note').textContent='Enter a whole number greater than zero.';return;}const count=Math.min(requested,availableExportCount);if(!count)return;downloadRuleFile(rankedRules.slice(0,count),`fastest_${count}_rules`);$('export-count-note').textContent=`Downloaded the ${count.toLocaleString()} fastest rules from ${availableExportCount.toLocaleString()} benchmarked rules.`;});
renderPie();renderLegend();renderTable();
</script></body></html>'''
        html = html.replace('__AETHER_REPORT_JSON__', data_json)
        output_path = os.path.join(self.output_dir, f"{filename}_interactive.html")
        with open(output_path, 'w', encoding='utf-8', newline='\n') as report_file:
            report_file.write(html)
        print(f"{Colors.GREEN}Interactive HTML report saved: {filename}_interactive.html{Colors.END}")
    def create_statistical_summary(self, rule_performance: List[Tuple[str, Dict]], filename: str, corpus_description: str = ""):
        if not rule_performance:
            print(f"{Colors.YELLOW}No performance data available for statistical summary{Colors.END}")
            return
        try:
            rules = [rule for rule, _ in rule_performance]
            times = [data.get('gpu_kernel_time_seconds', data.get('execution_time', float('inf'))) * 1_000_000
                     for _, data in rule_performance if np.isfinite(data.get('gpu_kernel_time_seconds', data.get('execution_time', float('inf'))))]
            cv_values = [(data.get('gpu_kernel_metrics') or data.get('metrics') or {}).get('cv_percent')
                         for _, data in rule_performance if (data.get('gpu_kernel_metrics') or data.get('metrics') or {}).get('cv_percent') is not None]
            ops_sec = [data.get('gpu_operations_per_sec', data.get('operations_per_sec', 0.0))
                       for _, data in rule_performance]
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
            fig.suptitle('Comprehensive Statistical Summary', fontsize=16, y=0.99)
            if corpus_description:
                fig.text(0.5, 0.962, corpus_description, ha='center', va='top', fontsize=10)
            plt.tight_layout(rect=(0, 0, 1, 0.94) if corpus_description else None)
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
            mode = performance_data.get('word_corpus_mode', 'unknown').replace('_', ' ').title()
            words = int(performance_data.get('test_words_count', 0) or 0)
            corpus_description = f'{mode} corpus · {words:,} words per rule' if words else ''
            validation_summary = performance_data.get('validation_summary') or {}
            self.create_statistical_summary(rp, filename, corpus_description=corpus_description)
            self.create_interactive_report(
                rp, filename, corpus_description=corpus_description,
                validation_summary=validation_summary,
                default_export_rule_count=getattr(self, 'default_export_rule_count', 500)
            )
            self.create_performance_distribution(rp, filename)
        print(f"{Colors.GREEN}Dashboard generation complete!{Colors.END}")

class RulePerformanceTester:
    def __init__(self, platform_index=0, device_index=0):
        self.visualizer = None
        self.output_dir = None
        self.last_validation_report = None
        self.active_rule_line_numbers = []
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
    
    @staticmethod
    def _make_diverse_word_variant(seed_word: bytes, seed_index: int, cycle_index: int) -> bytes:
        """Create a deterministic variant without changing length or character class.

        Lowercase letters remain lowercase, uppercase remain uppercase, digits
        remain digits, and non-alphanumeric bytes stay unchanged. This keeps
        the per-position character-class and word-length profile matched to the
        identical-dictionary mode while changing the actual input contents.
        """
        if cycle_index <= 0:
            return seed_word
        payload = (
            b"RULEOPS-AETHER-CORPUS-v1\0"
            + seed_word
            + seed_index.to_bytes(4, "little", signed=False)
            + cycle_index.to_bytes(8, "little", signed=False)
        )
        digest = hashlib.blake2s(payload, digest_size=32).digest()
        varied = bytearray(seed_word)
        for position, char in enumerate(seed_word):
            value = digest[position]
            if 97 <= char <= 122:       # a-z
                varied[position] = 97 + (value % 26)
            elif 65 <= char <= 90:      # A-Z
                varied[position] = 65 + (value % 26)
            elif 48 <= char <= 57:      # 0-9
                varied[position] = 48 + (value % 10)
            # Keep punctuation and other bytes unchanged.
        return bytes(varied)

    def setup_test_data(self, max_words: int = 1000, identical_dicts: bool = False):
        """Build an exactly-sized test corpus for either dictionary mode.

        Both modes always contain exactly ``max_words`` entries and therefore
        launch the same number of GPU work items per rule. The identical mode
        repeats the fixed seed dictionary; the diverse mode generates
        deterministic, length-preserving content variants from those seeds.
        """
        builtin_words = [
            b"password", b"123456", b"qwerty", b"letmein", b"welcome", b"monkey", b"dragon", b"master",
            b"hello", b"freedom", b"whatever", b"computer", b"internet", b"sunshine", b"princess", b"charlie"
        ]
        count = max(1, int(max_words))
        self.test_words_requested = count
        self.test_word_seed_count = len(builtin_words)
        self.word_corpus_mode = "identical" if identical_dicts else "diverse"
        self.word_corpus_generator = (
            "repeated_seed_dictionary" if identical_dicts
            else "deterministic_length_preserving_variants_v1"
        )

        if identical_dicts:
            self.test_words = [builtin_words[index % len(builtin_words)] for index in range(count)]
            mode_label = "Identical dictionary (16 seed words repeated)"
        else:
            self.test_words = [
                self._make_diverse_word_variant(
                    builtin_words[index % len(builtin_words)],
                    index % len(builtin_words),
                    index // len(builtin_words),
                )
                for index in range(count)
            ]
            mode_label = "Diverse dictionary (deterministic content variants)"

        # Store the profile for reports so the matched workload is auditable.
        length_counts = {}
        for word in self.test_words:
            key = str(len(word))
            length_counts[key] = length_counts.get(key, 0) + 1
        self.word_length_distribution = dict(sorted(length_counts.items(), key=lambda item: int(item[0])))

        print(f"{Colors.GREEN}{mode_label}{Colors.END}")
        print(f"{Colors.CYAN}Test words: {len(self.test_words):,} / {count:,} requested{Colors.END}")
        print(f"{Colors.CYAN}GPU work-items per rule: exactly {len(self.test_words):,} in either mode{Colors.END}")
        print(f"{Colors.CYAN}Word-length profile: {self.word_length_distribution}{Colors.END}")
        self.max_word_len = 64
        self.max_rule_len = 256
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
            if len(rule) >= self.max_rule_len:
                raise ValueError(
                    f"Rule at batch index {i} is {len(rule)} bytes; maximum supported is {self.max_rule_len - 1}"
                )
            rule_start = i * self.max_rule_len
            for j, char in enumerate(rule):
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
        base_name = output_basename or os.path.splitext(os.path.basename(rule_file_path))[0]
        if self.output_dir and self.last_validation_report:
            try:
                for path in write_validation_artifacts(self.last_validation_report, self.output_dir, base_name):
                    print(f"{Colors.CYAN}Validation artifact saved: {path}{Colors.END}")
            except Exception as exc:
                print(f"{Colors.YELLOW}Could not save validation artifacts: {exc}{Colors.END}")
        if not rules:
            print(f"{Colors.RED}No Aether-benchmarkable Hashcat rules found in {rule_file_path}{Colors.END}")
            return []
        if len(rules) > max_test_rules:
            print(f"{Colors.YELLOW}Limiting to first {max_test_rules} benchmarkable rules (out of {len(rules)}){Colors.END}")
            rules = rules[:max_test_rules]
            self.active_rule_line_numbers = self.active_rule_line_numbers[:max_test_rules]
        rule_performance = []
        total_rules = len(rules)
        successful_tests = 0
        for i, rule in enumerate(rules):
            rule_str = rule.decode('ascii', errors='strict')
            source_line_number = self.active_rule_line_numbers[i] if i < len(self.active_rule_line_numbers) else None
            print(f"{Colors.WHITE}  Testing rule {i+1}/{total_rules} (source line {source_line_number}): {Colors.YELLOW}{rule_str}{Colors.END}")
            performance_data = self.test_single_rule_performance(rule, test_runs)
            performance_data['source_line_number'] = source_line_number
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
            self.visualizer.generate_dashboard({
                'rule_performance': rule_performance,
                'test_runs': test_runs,
                'timestamp': datetime.now().isoformat(),
                'word_corpus_mode': self.word_corpus_mode,
                'test_words_count': len(self.test_words),
                'validation_summary': (self.last_validation_report or {}).get('summary', {}),
            }, base_name)
        return rule_performance
    
    def read_rules_from_file(self, file_path: str) -> List[bytes]:
        """Validate a Hashcat rule file before passing safe entries to OpenCL.

        The source-line mapping is retained so performance artifacts can point
        back to the exact original line. Invalid, CLI-only and currently
        unsupported commands are reported separately and never benchmarked.
        """
        try:
            self.last_validation_report = validate_rule_file(file_path)
            summary = self.last_validation_report["summary"]
            benchmark_rules = self.last_validation_report["benchmark_rules"]
            self.active_rule_line_numbers = [int(item["line_number"]) for item in benchmark_rules]
            rules = [str(item["rule"]).encode("ascii", errors="strict") for item in benchmark_rules]
            print(
                f"{Colors.GREEN}Aether validation: {summary['benchmarkable_rules']:,} benchmarkable; "
                f"{summary['invalid_rules']:,} invalid; {summary['cli_only_rules']:,} CLI-only; "
                f"{summary['unsupported_rules']:,} valid for Hashcat but unsupported by this Aether kernel; "
                f"{summary['comment_lines']:,} comments; {summary['blank_lines']:,} blank lines.{Colors.END}"
            )
            return rules
        except Exception as exc:
            self.last_validation_report = None
            self.active_rule_line_numbers = []
            print(f"{Colors.RED}Error validating rule file {file_path}: {exc}{Colors.END}")
            return []

    def save_sorted_rules(self, rule_performance: List[Tuple[str, Dict[str, Any]]], output_file: str):
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Rules sorted by performance (fastest first)\n")
                f.write(f"# Generated by RulePerformanceTester\n")
                f.write(f"# Total rules: {len(rule_performance)}\n")
                f.write(f"# Test words per rule: {len(getattr(self, 'test_words', []))}\n")
                f.write(f"# Dictionary mode: {getattr(self, 'word_corpus_mode', 'unknown')}\n")
                f.write(f"# Word-length distribution: {getattr(self, 'word_length_distribution', {})}\n")
                f.write(f"# Workload matched across dictionary modes: yes\n")
                f.write(f"# Test date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Primary metric: GPU kernel execution time from OpenCL event START..END timestamps\n")
                f.write(f"# End-to-end time includes host enqueue + queue completion wait (diagnostic only)\n")
                f.write(f"# Performance metadata is stored as standalone comments immediately before each rule.\n\n")
                for rule, perf_data in rule_performance:
                    source_line = perf_data.get('source_line_number')
                    if source_line is not None:
                        f.write(f"# Source line: {int(source_line)}\n")
                    f.write(
                        f"# GPU {perf_data['gpu_kernel_time_seconds']:.9f}s | "
                        f"E2E {perf_data['end_to_end_time_seconds']:.9f}s | "
                        f"{perf_data['gpu_operations_per_sec']:,.0f} GPU ops/sec | "
                        f"{perf_data['metrics']['cv_percent']:.1f}% CV\n"
                    )
                    # Hashcat rule files require comments to be standalone lines;
                    # never append diagnostic text to an executable rule command.
                    f.write(f"{rule}\n")
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
                    "requested_test_words_count": int(getattr(self, "test_words_requested", len(self.test_words))),
                    "gpu_work_items_per_rule": len(self.test_words),
                    "word_corpus_mode": getattr(self, "word_corpus_mode", "identical" if identical_dicts else "diverse"),
                    "word_corpus_generator": getattr(self, "word_corpus_generator", "unknown"),
                    "word_corpus_seed_words": int(getattr(self, "test_word_seed_count", 0)),
                    "word_length_distribution": getattr(self, "word_length_distribution", {}),
                    "workload_matched_across_corpus_modes": True,
                    "word_corpus_comparison_note": "Both modes use the same word count and per-position character-class/word-length profile; only word contents and repetition differ.",
                    "max_word_len": self.max_word_len,
                    "max_rule_len": self.max_rule_len,
                    "identical_dicts_mode": identical_dicts,
                    "timing_method": "opencl_event_profiling",
                    "opencl_profiling_enabled": bool(getattr(self, "profiling_enabled", False)),
                    "opencl_command_queue_property": "PROFILING_ENABLE",
                    "primary_time_metric": "gpu_kernel_time_seconds",
                    "rule_validation": (self.last_validation_report or {}).get("summary", {}),
                    "rule_validation_policy": "Hashcat 8 -r syntax plus sequential Aether OpenCL interpreter compatibility; supported command chains and h/H/S/v/B are benchmarked, unsupported commands are reported and not benchmarked.",
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
                        "source_line_number": perf_data.get("source_line_number"),
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

        # Validate again at the final write boundary. Input preflight protects the
        # GPU benchmark; this check protects the optimized .rule artifact itself.
        validation = validate_rule_records(all_rules)
        all_rules = validation["valid_rules"]
        validation_summary = validation["summary"]
        validation_issues = validation["issues"]
        if validation_issues:
            print(
                f"{Colors.YELLOW}Optimized output validation rejected "
                f"{len(validation_issues):,} rule(s); details are included in the optimization report.{Colors.END}"
            )

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
            f.write(
                f"# Candidate validation: {validation_summary['benchmarkable_rules']} valid; "
                f"{validation_summary['invalid_rules']} invalid; "
                f"{validation_summary['cli_only_rules']} CLI-only; "
                f"{validation_summary['unsupported_rules']} unsupported by Aether\n"
            )
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
            "rule_validation": {
                "summary": validation_summary,
                "rejected_rules": validation_issues,
            },
            "selected_rules": selected_rules
        }
        with open(report_file, 'w') as f:
            json.dump(optimization_report, f, indent=2)
        print(f"\n{Colors.GREEN}Optimized rule set created: {output_file}{Colors.END}")
        print(
            f"{Colors.CYAN}Final validation: {validation_summary['benchmarkable_rules']:,} valid, "
            f"{len(validation_issues):,} rejected.{Colors.END}"
        )
        print(f"{Colors.CYAN}Selected {len(selected_rules)} rules with cumulative GPU kernel time {total_time:.9f}s{Colors.END}")
        print(f"{Colors.CYAN}Optimization report: {report_file}{Colors.END}")

RULE_FILE_EXTENSIONS = frozenset({'.rule', '.rules', '.hr', '.hashcat', '.txt'})


def find_rule_files(rule_paths: List[str]) -> List[str]:
    """Resolve rule files using the same extensions accepted by the web UI."""
    rule_files = []
    for path in rule_paths:
        candidate = Path(path)
        if candidate.is_file():
            if candidate.suffix.lower() in RULE_FILE_EXTENSIONS:
                rule_files.append(str(candidate))
            else:
                accepted = ', '.join(sorted(RULE_FILE_EXTENSIONS))
                print(f"{Colors.YELLOW}Warning: {path} has an unsupported extension (accepted: {accepted}); skipping{Colors.END}")
        elif candidate.is_dir():
            rule_files_found = sorted(
                file_path for file_path in candidate.rglob('*')
                if file_path.is_file() and file_path.suffix.lower() in RULE_FILE_EXTENSIONS
            )
            if rule_files_found:
                rule_files.extend(str(file_path) for file_path in rule_files_found)
                print(f"{Colors.GREEN}Found {len(rule_files_found)} rule files in {path}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Warning: No supported rule files found in directory {path}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}Warning: Path not found: {path}{Colors.END}")
    return sorted(set(rule_files))


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
    parser.add_argument('--rules', '-r', nargs='+', required=True, help='Rule files (.rule, .rules, .hr, .hashcat, .txt) or directories containing them')
    parser.add_argument('--rule-labels', nargs='+', default=None, help='Optional display/output names aligned with --rules (used by the RULEOPS web UI to hide internal upload IDs)')
    parser.add_argument('--output', '-o', default='./benchmark_results', help='Output directory for results')
    parser.add_argument('--iterations', '-i', type=int, default=50, help='Number of test iterations per rule')
    parser.add_argument('--test-runs', type=int, default=3, help='Number of test runs per rule for statistical accuracy')
    parser.add_argument('--max-words', type=int, default=1000, help='Exact number of test words/work-items per rule in either corpus mode')
    parser.add_argument('--max-test-rules', type=int, default=1000, help='Maximum number of rules to test')
    parser.add_argument('--optimize', action='store_true', help='Create optimized rule set after benchmarking')
    parser.add_argument('--max-optimize-rules', type=int, default=500, help='Maximum rules for optimized set')
    parser.add_argument('--max-time', type=float, default=30.0, help='Maximum cumulative GPU kernel execution time in seconds for optimized set')
    parser.add_argument('--visualize', action='store_true', help='Generate PNG dashboards and interactive HTML rule-tier reports')
    parser.add_argument('--dpi', type=int, default=300, help='DPI for output images')
    parser.add_argument('--visualization-output', default=None, help='Separate output directory for visualizations')
    parser.add_argument('--platform', type=int, default=0, help='OpenCL platform index')
    parser.add_argument('--device', type=int, default=0, help='OpenCL device index')
    # ── Matched dictionary corpus modes ─────────────────────────────────────
    parser.add_argument(
        '--identical-dicts',
        action='store_true',
        help=(
            'Repeat the fixed 16-word seed dictionary to exactly --max-words entries. '
            'Without this flag, Aether creates deterministic content variants while '
            'preserving the same word-length and character-class profile. Both modes '
            'use exactly --max-words GPU work-items per rule.'
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
        tester.output_dir = args.output
        tester.iterations = args.iterations
        tester.default_export_rule_count = args.max_optimize_rules
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
        print(f"  {Colors.WHITE}Test words loaded:{Colors.END} {Colors.YELLOW}{len(tester.test_words):,}{Colors.END}")
        corpus_label = "Identical (seed dictionary repeated)" if args.identical_dicts else "Diverse (length-preserving variants)"
        print(f"  {Colors.WHITE}Dictionary mode:{Colors.END} {Colors.MAGENTA}{corpus_label}{Colors.END}")
        print(f"  {Colors.WHITE}GPU work-items per rule:{Colors.END} {Colors.YELLOW}{len(tester.test_words):,}{Colors.END} (matched across modes)")
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
