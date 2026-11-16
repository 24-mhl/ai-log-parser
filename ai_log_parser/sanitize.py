#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把模型返回的 JSON 和脚本算出的实际情况对齐。

为什么需要这一层：
    实测模型会做三件不该做的事 ——
    1. 给「正常业务」的 IP 编一个 verdict=得手
    2. evidence_lines 填了候选行里根本不存在的行号（比如 L31）
    3. 把 prompt 示例里的占位文字原样抄回来（"先封哪个 IP"）

    这三件事都能在本地用几十行代码判死，不该指望「改 prompt 让它别这样」。
    模型负责写叙述，事实核对交给脚本 —— 和「不让它数数」是同一个道理。
"""

import re

VERDICTS = ("得手", "未得手", "正常业务")
TIME_RE = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")

# prompt 里示例用的占位文字，模型偶尔会照抄
PLACEHOLDER = ("先封哪个", "查哪个文件", "具体动作", "哪个 IP", "哪个文件")


def _clean_ip(value):
    return (value or "").strip().strip("`").strip()


def sanitize(result, summary, picked):
    """返回修正后的 dict。summary 来自 prescreen.summarize()，picked 来自 select()。"""
    if not isinstance(result, dict):
        result = {}

    known_ips = {row["ip"] for row in summary}
    script_verdict = {row["ip"]: row["verdict"] for row in summary}
    lines_of = {}
    for _points, _reasons, rec in picked:
        lines_of.setdefault(rec.ip, set()).add(rec.no)

    findings = []
    for item in result.get("findings") or []:
        if not isinstance(item, dict):
            continue
        ip = _clean_ip(item.get("ip"))
        if ip not in known_ips:
            continue                     # 不认识的 IP，直接丢

        verdict = item.get("verdict")
        override = False
        if verdict not in VERDICTS:
            verdict, override = script_verdict[ip], True
        # 脚本算出来全是 2xx 的，不接受「得手」
        if script_verdict[ip] == "正常业务":
            override = override or verdict != "正常业务"
            verdict = "正常业务"

        # 正常业务不进判定表 —— 附录 A 已经有完整统计，混在一起只会稀释重点
        if verdict == "正常业务":
            continue

        lines = [n for n in (item.get("evidence_lines") or []) if n in lines_of.get(ip, set())]
        if not lines:
            # 判了得手/未得手却拿不出这个 IP 的真实行号，这条不可信
            continue

        reason = (item.get("reason") or "").strip()
        if override:
            reason = "（模型判定与状态码分布不符，已按脚本改正）%s" % reason

        findings.append({
            "ip": ip,
            "verdict": verdict,
            "evidence_lines": sorted(lines),
            "reason": reason,
        })

    covered = {f["ip"] for f in findings}
    for row in summary:
        if row["verdict"] == "正常业务" or row["ip"] in covered:
            continue
        findings.append({
            "ip": row["ip"],
            "verdict": row["verdict"],
            "evidence_lines": sorted(lines_of.get(row["ip"], [])),
            "reason": "（模型未覆盖，由脚本按状态码分布补齐）",
        })

    order = {"得手": 0, "未得手": 1, "正常业务": 2}
    findings.sort(key=lambda f: order.get(f["verdict"], 9))

    all_lines = set()
    for _points, _reasons, rec in picked:
        all_lines.add(rec.no)

    timeline = []
    for item in result.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        when = str(item.get("time") or "").strip()
        if not TIME_RE.match(when):
            continue                     # 0、空、乱写的都丢掉
        line = item.get("line")
        if line not in all_lines:
            line = None                  # 行号不在候选集里就不展示，别给假坐标
        timeline.append({
            "time": when,
            "line": line,
            "event": (item.get("event") or "").strip(),
        })
    timeline = timeline[:5]

    steps = []
    for step in result.get("next_steps") or []:
        text = str(step).strip()
        if not text or any(p in text for p in PLACEHOLDER):
            continue
        steps.append(text)

    attacker = _clean_ip(result.get("attacker_ip"))
    if attacker not in known_ips:
        attacker = ""

    return {
        "summary": (result.get("summary") or "").strip(),
        "attacker_ip": attacker,
        "timeline": timeline,
        "findings": findings,
        "next_steps": steps[:5],
    }
