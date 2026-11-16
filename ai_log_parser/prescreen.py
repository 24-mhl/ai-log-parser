#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则打分，从整份日志里挑出不超过 N 条最值得看的行。

两条设计原则：

1. **同一形态只留一条。**
   某个 IP 对着 /admin/login.php 撞了 22 次，把 22 行都喂给模型没有意义 ——
   模型要的是「形态」，不是「次数」。次数由 summarize() 算准了单独给它。

2. **分数必须有理由。**
   每一条命中的规则都写进 reasons，最后会原样出现在 prompt 里，
   让模型知道「为什么这行被挑出来」，而不是凭空猜。

这套规则不是安全产品的检测引擎，它的目标只有一个：
把 206 行压到 20 行，且不漏掉「得手」的那一条。
"""

from .reader import hour_of

# 攻击者常试的路径。命中一个就加分，命中的关键字会写进理由。
SENSITIVE = (
    "/.env", "/.git", "config", ".bak", "/admin", "/upload",
    "phpmyadmin", "/manager", "phpinfo", ".sql", "wp-login", "xmlrpc",
)

# 扫描器的 UA 特征。正常浏览器不会带这些词。
SCANNER_UA = (
    "nmap", "sqlmap", "nikto", "masscan", "gobuster", "dirbuster",
    "zgrab", "curl", "python-requests", "wpscan", "nuclei", "uptimerobot",
)


def score(record, first_win_no=None):
    """返回 (分数, 理由列表)。0 分表示这行不值得看。

    first_win_no 是这个 IP 第一次出现 302 的行号。传进来的话，
    302 之后的状态码 200 会被加权重 —— 那是「进去以后干了什么」，
    比在门外敲了几十下更有价值。
    """
    points = 0
    reasons = []

    # 认证失败/成功：爆破的原料和结果
    if record.status in (401, 403):
        points += 3
        reasons.append("认证被拒 %d" % record.status)
    elif record.status == 302 and "login" in record.path.lower():
        points += 4
        reasons.append("登录后跳转 302（可能是成功）")
    elif record.status >= 500:
        points += 4
        reasons.append("服务端错误 %d（可能打崩了）" % record.status)

    # 路径
    low_path = record.path.lower()
    for keyword in SENSITIVE:
        if keyword in low_path:
            points += 2
            reasons.append("敏感路径 %s" % keyword)
            break

    # 目录穿越
    if "../" in low_path or "%2e%2e" in low_path:
        points += 3
        reasons.append("疑似目录穿越")

    # 上传/导出这类「干完活」的接口。
    # 只认这几个具体的词，不能按 .php 一刀切 —— 否则 /index.php、/product.php
    # 这种正常页面会全部命中，把名额吃光。这个坑踩过一次。
    if any(k in low_path for k in ("/upload", "/export", "/download")):
        points += 2
        reasons.append("敏感接口 %s" % record.path)

    # 请求方法
    if record.method not in ("GET", "POST"):
        points += 2
        reasons.append("异常方法 %s" % record.method)

    # UA
    low_ua = record.ua.lower()
    for keyword in SCANNER_UA:
        if keyword in low_ua:
            points += 3
            reasons.append("工具 UA：%s" % keyword)
            break

    # 凌晨活动：正常员工不会在 2 点操作后台
    if 0 <= hour_of(record) < 6 and record.status not in (200, 302):
        points += 1
        reasons.append("凌晨时段")

    # 得手之后的操作：登录成功之后还在访问后台接口，
    # 这是「已经进去了」的直接证据，比门外敲几十下重要得多
    if first_win_no and record.no > first_win_no and 200 <= record.status < 300:
        points += 4
        reasons.append("登录成功之后的操作")

    return points, reasons


def first_success(records):
    """每个 IP 第一次出现 302 的行号。302 是登录成功后跳转，最容易识别的信号。"""
    first = {}
    for rec in records:
        if rec.status == 302 and rec.ip not in first:
            first[rec.ip] = rec.no
    return first


def select(records, limit=20, per_ip=4):
    """按分数挑行，返回 [(分数, 理由, 记录), ...]。

    选择顺序分三步，顺序不能换：

    1. **必选**：出现过 302 的 IP，那一行 302 一定要在。
       它是「进去了」的唯一证据，被分数挤掉就等于丢结论。
    2. **必选**：同一 IP 里分数最高的那条 401/403，代表它敲门的手法。
    3. **补足**：剩下按分数填，每个 IP 最多 per_ip 种形态。

    有得手的 IP 额外多给两个名额 —— 进去以后干了什么，比门外敲了多少下更值得看。
    """
    wins = first_success(records)

    # (ip, 方法, 路径, 状态码) 相同的视为同一形态，只留分数最高的那条
    shapes = {}
    for rec in records:
        points, reasons = score(rec, first_win_no=wins.get(rec.ip))
        if points <= 0:
            continue
        key = (rec.ip, rec.method, rec.path, rec.status)
        current = shapes.get(key)
        if current is None or points > current[0]:
            shapes[key] = (points, reasons, rec)

    by_ip = {}
    for (ip, _m, _p, _s), item in shapes.items():
        by_ip.setdefault(ip, []).append(item)
    for items in by_ip.values():
        items.sort(key=lambda x: (-x[0], x[2].no))

    picked = []
    for ip, items in by_ip.items():
        budget = per_ip + 2 if ip in wins else per_ip
        chosen = []

        # 1. 登录成功那一行
        for item in items:
            if item[2].status == 302:
                chosen.append(item)
                break
        # 2. 分数最高的认证失败那一行
        for item in items:
            if item[2].status in (401, 403):
                chosen.append(item)
                break
        # 3. 补足
        for item in items:
            if len(chosen) >= budget:
                break
            if item not in chosen:
                chosen.append(item)
        picked.extend(chosen[:budget])

    picked.sort(key=lambda x: (-x[0], x[2].no))
    return picked[:limit]


def summarize(records):
    """按 IP 汇总状态码分布，并按「有没有得手」分组。

    返回 [{ip, dist, fails, wins, verdict}, ...]，
    有得手的排前面 —— 排序规则本身就是给模型的提示。
    """
    counts = {}
    for rec in records:
        counts.setdefault(rec.ip, {})
        counts[rec.ip][rec.status] = counts[rec.ip].get(rec.status, 0) + 1

    rows = []
    for ip, dist in counts.items():
        fails = dist.get(401, 0) + dist.get(403, 0)
        wins = dist.get(302, 0) + sum(v for k, v in dist.items() if 200 <= k < 300)
        if fails > 0 and wins > 0:
            verdict, weight = "失败后成功", 0
        elif fails > 0:
            verdict, weight = "零得手", 1
        else:
            verdict, weight = "正常业务", 2
        rows.append({
            "ip": ip,
            "dist": dict(sorted(dist.items())),
            "fails": fails,
            "wins": wins,
            "verdict": verdict,
            "_weight": weight,
        })

    rows.sort(key=lambda r: (r["_weight"], [int(p) for p in r["ip"].split(".")]))
    for row in rows:
        row.pop("_weight")
    return rows


def table_text(summary):
    """把 summarize() 的结果排成等宽表格，直接拼进 prompt。"""
    lines = ["IP               判定          状态码分布"]
    for row in summary:
        dist = "  ".join("%d×%d" % (k, v) for k, v in row["dist"].items())
        lines.append("%-16s %-12s %s" % (row["ip"], row["verdict"], dist))
    return "\n".join(lines)


def lines_text(picked):
    """把挑出的行排成「行号 | 理由 | 原文」，行号必须保留。"""
    out = []
    for points, reasons, rec in picked:
        raw = '%s - - [%s] "%s %s HTTP/1.1" %d %s "%s" "%s"' % (
            rec.ip, rec.time, rec.method, rec.path,
            rec.status, rec.size, rec.referer, rec.ua[:60],
        )
        out.append("%4d | %s（%d分） | %s" % (
            rec.no, "、".join(reasons), points, raw,
        ))
    return "\n".join(out)
