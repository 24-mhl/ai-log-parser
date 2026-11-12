#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手写练习版 —— 照着「读日志 → 拼 prompt → POST → 打印结论」四步一步步敲出来的。

和 api.py 的关系：
    这份是 2026-11-11 夜里写的第一版，边学边写，全平铺，没有函数、没有参数解析。
    api.py 是在它的基础上整理的成品：抽出函数、加了 --dry-run / --max-chars / 错误翻译。
    保留它是因为三次 prompt 迭代的痕迹都在这里：

    第 1 问末尾那段「排序依据：先按日志里是否出现过 2xx 或 302 分成两组……」
    是第三版才加进去的。加之前模型把「38 次全失败的扫描器」和真凶排在同一档；
    加之后扫描器降级了，但把正常登录的员工也拖进了嫌疑人名单。

    结论：让脚本数数，让模型写话。见 README「设计取舍」和 notes 里的 day7。

写法上刻意保留的两点：
    - prompt 用字符串拼接而不是 .format()，所以日志里出现 {} 也不会抛 KeyError
    - 先做三次 print 自检（字符数 / 开头 80 字 / 结尾 200 字）再发请求，
      不花钱就能确认拼接对不对

用法：
    python practice.py
"""

LOG = r"C:\Users\麓山阁\Desktop\CTF环境\应急靶场\access.log"
import os
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()

print(len(text))
print(text[:80])
PROMPT="""下面是一份web访问日志，请按四个问题做初筛:

1.谁在打:列出可疑来源IP,按危险程度排序，并说明判断依据。排序依据：先按「日志里是否出现过 2xx 或 302」分成两组，有成功的排前面；
全部是 4xx 的单独归为一组，标注「仅探测、未得手」。
不要按请求条数或工具类型排序。
2.什么时候，具体攻击的时间段。
3.打哪里：被重点检测的路径，以及尝试了什么手法（注入/扫描/爆破等）。
4.有没有得手：指出最像成功的那几条，并说明为什么。


最后用一句话给出优先级建议。

日志如下：

---

""" + text

print("prompt 总长：",len(PROMPT))
print("--- 开头 300 字 ---")
print(PROMPT[:300])
print("--- 结尾 200 字 ---")
print(PROMPT[-200:])      
key = ""
with open(".env", encoding="utf-8") as f:
    for line in f:
        if line.startswith("ZHIPU_API_KEY="):
            key = line.split("=", 1)[1].strip()

print("key 长度：", len(key))
import json
import urllib.request
import urllib.error

body = {
    "model": "glm-4-flash",
    "messages": [
        {"role": "system", "content": "你是做应急响应的安全工程师。只根据日志回答，不要补充日志里没有的信息。"},
        {"role": "user", "content": PROMPT},
    ],
    "temperature": 0.2,
}

req = urllib.request.Request(
    "https://open.bigmodel.cn/api/paas/v4/chat/completions",
    data=json.dumps(body).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + key,
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read().decode("utf-8"))
except urllib.error.HTTPError as e:
    print("HTTP", e.code)
    print(e.read().decode("utf-8", "replace")[:500])
    raise SystemExit(1)

print("token：", data["usage"])
print(data["choices"][0]["message"]["content"])
