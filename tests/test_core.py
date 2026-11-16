#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试：解析、打分、校验三层各测一遍。

这些测试不联网，跑一次不到一秒，改了规则就能立刻知道有没有把老行为改坏：
    python -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_log_parser import prescreen, sanitize  # noqa: E402
from ai_log_parser.reader import parse_line, read  # noqa: E402

LINE_401 = ('198.18.44.91 - - [07/Nov/2026:02:04:02 +0800] '
            '"POST /admin/login.php HTTP/1.1" 401 231 "/admin/login.php" '
            '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"')
LINE_302 = ('198.18.44.91 - - [07/Nov/2026:02:19:47 +0800] '
            '"POST /admin/login.php HTTP/1.1" 302 0 "/admin/login.php" '
            '"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"')
LINE_200 = ('192.0.2.31 - - [07/Nov/2026:22:31:16 +0800] '
            '"GET /api/orders?page=2 HTTP/1.1" 200 15220 "/" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"')
LINE_NMAP = ('203.0.113.77 - - [07/Nov/2026:02:43:10 +0800] '
             '"GET /manager/html HTTP/1.1" 403 162 "-" '
             '"Mozilla/5.0 (compatible; Nmap Scripting Engine)"')


def make_records():
    return [parse_line(line, no) for no, line in
            enumerate([LINE_401, LINE_302, LINE_200, LINE_NMAP], 1)]


class TestReader(unittest.TestCase):
    def test_parse_fields(self):
        rec = parse_line(LINE_401, 8)
        self.assertEqual(rec.no, 8)
        self.assertEqual(rec.ip, "198.18.44.91")
        self.assertEqual(rec.method, "POST")
        self.assertEqual(rec.path, "/admin/login.php")
        self.assertEqual(rec.status, 401)
        self.assertIn("Linux", rec.ua)

    def test_ua_with_spaces_does_not_shift_status(self):
        # UA 里带空格，用 split 的话状态码位置会漂；正则按引号整体匹配才稳
        rec = parse_line(LINE_200, 1)
        self.assertEqual(rec.status, 200)
        self.assertEqual(rec.path, "/api/orders?page=2")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_line("this is not a log line", 1))
        self.assertIsNone(parse_line("", 2))


class TestPrescreen(unittest.TestCase):
    def test_401_scores_positive(self):
        points, reasons = prescreen.score(parse_line(LINE_401, 1))
        self.assertGreater(points, 0)
        self.assertTrue(any("401" in r for r in reasons))

    def test_normal_traffic_scores_zero(self):
        points, _ = prescreen.score(parse_line(LINE_200, 1))
        self.assertEqual(points, 0)

    def test_verdict_after_bruteforce(self):
        summary = prescreen.summarize(make_records())
        row = [r for r in summary if r["ip"] == "198.18.44.91"][0]
        self.assertEqual(row["verdict"], "失败后成功")
        self.assertEqual(row["fails"], 1)

    def test_scan_only_is_zero_gain(self):
        summary = prescreen.summarize([parse_line(LINE_NMAP, 1)])
        self.assertEqual(summary[0]["verdict"], "零得手")
        self.assertEqual(summary[0]["wins"], 0)

    def test_select_keeps_302_even_when_score_low(self):
        # 302 是「进去了」的唯一证据，分数再低也必须留在候选里
        picked = prescreen.select(make_records(), limit=10, per_ip=1)
        statuses = [rec.status for _p, _r, rec in picked]
        self.assertIn(302, statuses)


class TestSanitize(unittest.TestCase):
    def setUp(self):
        self.records = make_records()
        self.summary = prescreen.summarize(self.records)
        self.picked = prescreen.select(self.records, limit=10, per_ip=4)

    def test_drops_unknown_ip(self):
        # 模型编出来的 IP 必须被剔除；同时脚本会把漏掉的真实 IP 补上，
        # 所以这里断言的是「9.9.9.9 不出现」，不是「结果为空」
        result = {"findings": [{"ip": "9.9.9.9", "verdict": "得手", "evidence_lines": [1]}]}
        cleaned = sanitize.sanitize(result, self.summary, self.picked)
        self.assertTrue(all(f["ip"] != "9.9.9.9" for f in cleaned["findings"]))
        self.assertTrue(cleaned["findings"], "脚本应补齐模型漏掉的 IP")

    def test_drops_fake_line_numbers(self):
        result = {"findings": [{"ip": "198.18.44.91", "verdict": "得手",
                                "evidence_lines": [9999], "reason": "编的"}]}
        cleaned = sanitize.sanitize(result, self.summary, self.picked)
        self.assertTrue(all(9999 not in f["evidence_lines"] for f in cleaned["findings"]))

    def test_normal_traffic_cannot_be_attacker(self):
        result = {"findings": [{"ip": "192.0.2.31", "verdict": "得手", "evidence_lines": [3]}]}
        cleaned = sanitize.sanitize(result, self.summary, self.picked)
        self.assertTrue(all(f["ip"] != "192.0.2.31" for f in cleaned["findings"]))

    def test_placeholder_steps_removed(self):
        result = {"next_steps": ["先封哪个 IP", "封禁 198.18.44.91"]}
        cleaned = sanitize.sanitize(result, self.summary, self.picked)
        self.assertEqual(cleaned["next_steps"], ["封禁 198.18.44.91"])

    def test_bad_time_dropped(self):
        result = {"timeline": [{"time": 0, "event": "x"}, {"time": "02:04:02", "event": "y"}]}
        cleaned = sanitize.sanitize(result, self.summary, self.picked)
        self.assertEqual([t["time"] for t in cleaned["timeline"]], ["02:04:02"])


if __name__ == "__main__":
    unittest.main()
