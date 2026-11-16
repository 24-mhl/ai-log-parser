#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""命令行入口。

    python -m ai_log_parser access.log                  # 报告打到终端
    python -m ai_log_parser access.log -o report.md     # 写文件
    python -m ai_log_parser access.log --dry-run        # 只看预筛结果，不花钱
    python -m ai_log_parser access.log --max-lines 30   # 多喂几条

设计上的一处取舍：预筛结果无论跑不跑模型都会打印一行摘要
（原始行数 → 候选行数），这样 --dry-run 就能直接看出规则调得对不对，
不用等模型返回。
"""

import argparse
import json
import os
import sys

from .llm import DEFAULT_MODEL, ZhipuError, build_prompt, call, extract_json, load_env
from .prescreen import lines_text, score, select, summarize, table_text
from .reader import read
from .report import render
from .sanitize import sanitize


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ai_log_parser",
        description="Web 访问日志应急初筛：规则预筛 + 大模型叙述",
    )
    parser.add_argument("log", help="access.log 路径")
    parser.add_argument("-o", "--out", help="把 markdown 报告写到这个文件")
    parser.add_argument("--dry-run", action="store_true",
                        help="只做预筛、打印将要发送的 prompt，不发请求")
    parser.add_argument("--max-lines", type=int, default=20,
                        help="最多送多少条候选行给模型，默认 20")
    parser.add_argument("--per-ip", type=int, default=4,
                        help="每个 IP 最多保留几种请求形态，默认 4")
    parser.add_argument("--model", default=os.environ.get("GLM_MODEL", DEFAULT_MODEL),
                        help="模型名，默认 %s" % DEFAULT_MODEL)
    parser.add_argument("--json", dest="json_out", help="把模型原始 JSON 另存一份")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if not os.path.isfile(args.log):
        print("[!] 日志不存在：%s" % args.log, file=sys.stderr)
        return 2

    records, skipped = read(args.log)
    if not records:
        print("[!] 一行都没解析出来，确认是 Apache/Nginx access 格式", file=sys.stderr)
        return 2

    summary = summarize(records)
    picked = select(records, limit=args.max_lines, per_ip=args.per_ip)

    print("[i] %s：解析 %d 行，跳过 %d 行" % (args.log, len(records), len(skipped)))
    print("[i] 预筛：%d 行 → %d 条候选" % (len(records), len(picked)))
    for row in summary:
        print("    %-16s %-12s 401/403×%d  2xx/302×%d"
              % (row["ip"], row["verdict"], row["fails"], row["wins"]))

    if not picked:
        print("[!] 没有命中任何规则。这份日志可能都是正常流量，"
              "或者格式和预期不同。", file=sys.stderr)
        return 1

    prompt = build_prompt(table_text(summary), lines_text(picked),
                          total=len(records), picked=len(picked))

    if args.dry_run:
        print("-" * 64)
        print(prompt)
        print("-" * 64)
        print("[i] dry-run：没有发请求，不消耗额度")
        return 0

    load_env()
    api_key = os.environ.get("ZHIPU_API_KEY", "").strip()
    if not api_key:
        print("[!] 没有找到 ZHIPU_API_KEY：cp .env.example .env 后把 Key 填进去",
              file=sys.stderr)
        return 2

    print("[i] 调用 %s …" % args.model)
    try:
        content, usage = call(api_key, prompt, args.model)
        result = sanitize(extract_json(content), summary, picked)
    except ZhipuError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print("[i] 模型原始 JSON 已存到 %s" % args.json_out)

    meta = {
        "log": args.log,
        "total": len(records),
        "picked": len(picked),
        "model": args.model,
        "tokens": usage,
    }
    markdown = render(result, meta, summary=summary, picked=picked)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print("[i] 报告已写入 %s（%d 字）" % (args.out, len(markdown)))
        print("[i] token 用量：输入 %s / 输出 %s"
              % (usage.get("prompt_tokens", "?"), usage.get("completion_tokens", "?")))
    else:
        print("-" * 64)
        print(markdown)
        print("-" * 64)
        print("[i] token 用量：输入 %s / 输出 %s"
              % (usage.get("prompt_tokens", "?"), usage.get("completion_tokens", "?")))
    return 0


def _score_only(argv=None):        # pragma: no cover - 调试用，不参与主流程
    """打印每一行的得分，调规则的时候用。"""
    args = argv if argv is not None else sys.argv[1:]
    records, _ = read(args[0])
    for rec in records:
        points, reasons = score(rec)
        if points:
            print("L%-5d %-3d %s" % (rec.no, points, "、".join(reasons)))


if __name__ == "__main__":
    raise SystemExit(main())
