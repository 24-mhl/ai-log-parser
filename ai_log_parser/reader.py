#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 access.log 解析成结构化记录。

为什么用正则而不是 split()：
    access 的请求行和 UA 都在双引号里，UA 本身带空格
    （`Mozilla/5.0 (X11; Linux x86_64) ...`），
    split 之后字段位置会漂，第 9 个字段不一定还是状态码。
    正则按「引号整体」匹配，位置才稳定。

支持 Apache/Nginx 的 common 与 combined 两种格式，
combined 多出 referer 和 UA 两段，正则里做成可选。
"""

import re
from collections import namedtuple

# no 是原始行号（从 1 开始），报告里的「证据行」直接引用它。
Record = namedtuple(
    "Record",
    "no ip time method path status size referer ua",
)

LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'          # 客户端 IP，后面两个是 ident 和 user（通常是 -）
    r'\[(?P<time>[^\]]+)\]\s+'              # [07/Nov/2026:02:04:02 +0800]
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]*"\s+'   # "POST /admin/login.php HTTP/1.1"
    r'(?P<status>\d{3})\s+(?P<size>\S+)'    # 401 231
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'    # "-" "Mozilla/5.0 ..."
)


def parse_line(line, no):
    """解析一行，认不出来返回 None。

    认不出来不抛异常 —— 真实日志里总有几条被写坏的，
    一条坏行不该让整次分析失败。
    """
    m = LINE_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    return Record(
        no=no,
        ip=m["ip"],
        time=m["time"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        size=m["size"],
        referer=m["referer"] or "",
        ua=m["ua"] or "",
    )


def read(path):
    """读日志，返回 (记录列表, 无法解析的行号列表)。"""
    records, skipped = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = parse_line(line, no)
            if rec is None:
                skipped.append(no)
            else:
                records.append(rec)
    return records, skipped


def hour_of(record):
    """从 `07/Nov/2026:02:04:02 +0800` 里取小时，用来判断凌晨活动。"""
    try:
        return int(record.time.split(":")[1])
    except (IndexError, ValueError):
        return -1
