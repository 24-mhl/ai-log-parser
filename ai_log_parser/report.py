#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把模型返回的 dict 渲染成 markdown 报告。

为什么所有取值都用 .get() 并给默认值：
    模型返回的 JSON 字段名不一定齐全，少一个 key 就抛 KeyError 的话，
    整份报告都出不来。这里宁可少一行内容，也要把报告写完整。

为什么把统计和候选行放进附录：
    结论可以被质疑，原始依据不能丢。看报告的人要能一眼回到第 30 行。
"""

from datetime import datetime

VERDICT_ORDER = {"得手": 0, "未得手": 1, "正常业务": 2}


def _cells(values):
    return " | ".join("—" if v in (None, "", []) else str(v) for v in values)


def _time_text(value):
    """模型有时会把 time 写成 0 或漏掉，统一处理成「—」。"""
    if value in (None, "", 0, "0", "-"):
        return "—"
    return str(value)


def render(result, meta, summary=None, picked=None):
    """返回 markdown 文本。result 是模型给的 dict，meta 是本次运行的元信息。"""
    if not isinstance(result, dict):
        result = {}

    out = []
    out.append("# 应急初筛报告")
    out.append("")
    out.append("| 项 | 值 |")
    out.append("|---|---|")
    out.append("| 日志 | `%s` |" % meta.get("log", "-"))
    out.append("| 原始行数 | %s |" % meta.get("total", "-"))
    out.append("| 送入模型 | %s 条候选行 |" % meta.get("picked", "-"))
    out.append("| 模型 | `%s` |" % meta.get("model", "-"))
    if meta.get("tokens"):
        out.append("| token | 输入 %s / 输出 %s |" % (
            meta["tokens"].get("prompt_tokens", "?"),
            meta["tokens"].get("completion_tokens", "?")))
    out.append("| 生成时间 | %s |" % datetime.now().strftime("%Y-%m-%d %H:%M"))
    out.append("")

    out.append("## 一、结论")
    out.append("")
    out.append(result.get("summary") or "（模型没有给出结论）")
    out.append("")
    attacker = result.get("attacker_ip") or ""
    out.append("**最可疑来源**：%s" % ("`%s`" % attacker if attacker else "未能判断"))
    out.append("")

    timeline = result.get("timeline") or []
    if timeline:
        out.append("## 二、时间线")
        out.append("")
        out.append("| 时间 | 行号 | 事件 |")
        out.append("|---|---|---|")
        for item in timeline:
            if isinstance(item, dict):
                line = item.get("line")
                out.append("| %s | %s | %s |" % (
                    _time_text(item.get("time")),
                    "L%s" % line if line else "—",
                    item.get("event", ""),
                ))
        out.append("")

    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    # 模型可能只写最可疑那一个 IP。统计表里判定为「非正常业务」的 IP 必须都出现，
    # 缺的由脚本按状态码分布补齐 —— 报告的覆盖面不该取决于模型当时的心情。
    if summary:
        covered = {f.get("ip") for f in findings}
        for row in summary:
            if row["verdict"] == "正常业务" or row["ip"] in covered:
                continue
            findings.append({
                "ip": row["ip"],
                "verdict": row["verdict"],
                "evidence_lines": [],
                "reason": "（模型未覆盖，由脚本按状态码分布补齐："
                          "401/403×%d、2xx/302×%d）" % (row["fails"], row["wins"]),
            })
    if findings:
        findings.sort(key=lambda f: VERDICT_ORDER.get(f.get("verdict"), 9))
        out.append("## 三、逐个来源判定")
        out.append("")
        out.append("| IP | 判定 | 证据行 | 理由 |")
        out.append("|---|---|---|---|")
        for item in findings:
            lines = item.get("evidence_lines") or []
            refs = "、".join("L%s" % n for n in lines) if lines else "—"
            out.append("| `%s` | %s | %s | %s |" % (
                item.get("ip", "-"),
                item.get("verdict", "-"),
                refs,
                (item.get("reason") or "").replace("|", "/"),
            ))
        out.append("")
        out.append("> 「得手」只代表这个 IP 登录成功过，不等于它就是攻击者 —— "
                   "本人忘密码也是 401 之后 302。区分靠 401 的次数："
                   "半小时内几十次是脚本，几分钟内个位数是人。见附录 A。")
        out.append("")

    steps = result.get("next_steps") or []
    if steps:
        out.append("## 四、下一步")
        out.append("")
        for i, step in enumerate(steps, 1):
            out.append("%d. %s" % (i, step))
        out.append("")

    if summary:
        out.append("## 附录 A · 来源 IP 统计（脚本计算，非模型输出）")
        out.append("")
        out.append("| IP | 判定 | 状态码分布 | 401/403 | 2xx/302 |")
        out.append("|---|---|---|---|---|")
        for row in summary:
            dist = "  ".join("%d×%d" % (k, v) for k, v in row["dist"].items())
            out.append("| `%s` | %s | %s | %d | %d |" % (
                row["ip"], row["verdict"], dist, row["fails"], row["wins"]))
        out.append("")

    if picked:
        out.append("## 附录 B · 预筛候选行（%d 条）" % len(picked))
        out.append("")
        out.append("```")
        for _points, reasons, rec in picked:
            out.append("L%-5d %s %s %s → %d   [%s]" % (
                rec.no, rec.ip, rec.method, rec.path, rec.status, "、".join(reasons)))
        out.append("```")
        out.append("")

    out.append("---")
    out.append("")
    out.append("> 结论由 `%s` 生成，统计与行号由脚本计算。"
               "任何一条判定都应回到原始日志对应行复核后再行动。" % meta.get("model", "模型"))
    return "\n".join(out)
