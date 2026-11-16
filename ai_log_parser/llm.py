#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调 GLM，要求它返回 JSON。

两个刻意的选择：

1. **不把行号交给模型算。**
   v0.1 要求它「引用具体行号」，它在 206 行里编了一个不存在的「第 198 行」。
   v0.2 改成：行号由脚本在候选行前面标好，模型只能从里面挑。

2. **不依赖 response_format 参数。**
   不同模型对该参数的支持不一致，传了不支持的字段会直接 400。
   改成在 prompt 里写死输出格式，再用 extract_json() 做容错解析 ——
   模型爱加 ```json 围栏也不影响。
"""

import json
import os
import re
import urllib.error
import urllib.request

ENDPOINT = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
DEFAULT_MODEL = "glm-4-flash"

SYSTEM_PROMPT = (
    "你是做应急响应的安全工程师。只根据用户给的材料回答，不要补充材料里没有的信息。"
    "材料里看不出来的，就写「材料中无法判断」，不要猜。"
)

USER_TEMPLATE = """下面是一份 Web 访问日志的**预筛结果**，不是全文。原始日志共 {total} 行，按规则挑出 {picked} 条。

## 一、按来源 IP 的统计（数字由脚本算准，可直接引用）

<<TABLE>>

## 二、候选可疑行（格式：行号 | 命中规则 | 原始日志）

<<LINES>>

## 三、任务

按四问作答，**只输出一个 JSON 对象**，不要任何解释文字，不要用 ``` 包裹。

{
  "summary": "（一句话结论，不超过 40 字）",
  "attacker_ip": "（最可疑的来源 IP，判断不出来就空字符串）",
  "timeline": [{"time": "HH:MM:SS", "line": （候选行号）, "event": "（发生了什么）"}],
  "findings": [
    {"ip": "（IP）", "verdict": "得手", "evidence_lines": [（候选行号）], "reason": "（依据）"},
    {"ip": "（IP）", "verdict": "未得手", "evidence_lines": [（候选行号）], "reason": "（依据）"}
  ],
  "next_steps": ["（具体动作一）", "（具体动作二）"]
}

上面括号里是**占位说明，不是内容**，请全部换成你的实际结论，不要照抄。

硬性要求：

- verdict 只能是「得手」「未得手」「正常业务」三者之一
- evidence_lines 里的数字必须出现在上面候选行的**行号列**，禁止自己编号
- 判「得手」必须有 2xx 或 302 支撑；只有 4xx 的一律写「未得手」
- 只有 2xx 的正常流量写「正常业务」，不要当攻击者
- **findings 里只写「失败后成功」和「零得手」的 IP**，正常业务的不必列
- **timeline 的 time 必须是 HH:MM:SS 格式，从原始日志的时间戳里摘**（如 02:04:02），
  不许写 0、不许省略；`line` 填这条事件对应的候选行号
- timeline 最多 5 条，按时间先后
- next_steps 写具体动作，例如「封禁某 IP」「检查某文件是否还在」
"""


class ZhipuError(RuntimeError):
    """调用失败时抛出，message 已经是能直接给人看的中文。"""


def load_env(path=".env"):
    """读 KEY=VALUE 到环境变量。已存在的环境变量不覆盖。"""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip('"').strip("'")


def build_prompt(table, lines, total, picked):
    """拼 prompt。用 replace 而不是 format —— 候选行里出现 {} 也不会炸。"""
    return (USER_TEMPLATE
            .replace("{total}", str(total))
            .replace("{picked}", str(picked))
            .replace("<<TABLE>>", table)
            .replace("<<LINES>>", lines))


def call(api_key, prompt, model=DEFAULT_MODEL, timeout=90):
    """发一次请求，返回 (内容字符串, usage dict)。"""
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "stream": False,
    }
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ZhipuError(_explain_http(exc))
    except urllib.error.URLError as exc:
        raise ZhipuError("连不上 open.bigmodel.cn：%s（检查网络或代理）" % exc.reason)

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ZhipuError("响应结构不对：%s" % json.dumps(data, ensure_ascii=False)[:300])
    return content, data.get("usage") or {}


def _explain_http(exc):
    if exc.code == 401:
        return "401 鉴权失败：Key 抄错、带空格，或已被删除。"
    if exc.code == 429:
        return "429 限流或额度用尽：等几分钟再试。"
    if exc.code == 404:
        return "404 地址不对：确认是 /api/paas/v4/chat/completions，不是老的 v3。"
    body = ""
    try:
        body = exc.read().decode("utf-8", "replace")[:300]
    except Exception:            # noqa: BLE001  错误正文读不出来不该盖住原错误
        pass
    return "HTTP %d：%s" % (exc.code, body or exc.reason)


def extract_json(text):
    """从模型输出里抠出 JSON。

    模型经常不听话：加 ```json 围栏、前面写「好的，这是分析：」。
    这里三层兜底：直接解析 → 去围栏 → 截第一个 { 到最后一个 }。
    """
    raw = (text or "").strip()
    for candidate in (raw, _strip_fence(raw), _slice_braces(raw)):
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ZhipuError("模型返回的不是可解析的 JSON。原始输出前 300 字：\n%s" % raw[:300])


def _strip_fence(text):
    if not text.startswith("```"):
        return ""
    body = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    return re.sub(r"\s*```$", "", body)


def _slice_braces(text):
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return ""
    return text[start:end + 1]
