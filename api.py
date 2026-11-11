#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 Web 访问日志交给 GLM，让模型做一次「应急初筛」。

用法:
    python api.py ../logs/access.log                 # 直接出报告
    python api.py access.log --max-chars 6000        # 日志太长时截断到 6000 字符
    python api.py access.log --dry-run               # 只打印将要发送的 prompt，不花钱
    python api.py access.log --json out.json         # 顺便把原始响应存下来

为什么只用标准库：
    这台机器上 pip 走代理会 502，装 requests 反而多一道坎。
    urllib 够用，而且换台机器直接能跑。

为什么不让模型从头读整份日志：
    模型对「哪一行」并不敏感，长日志里它会开始编。
    v0.1 先把日志截到合理长度、把四问问清楚；
    v0.2 再加正则预筛，只喂可疑的几十条（见 README 的路线图）。
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

ENDPOINT = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
DEFAULT_MODEL = "glm-4-flash"
# 206 行的典型 access.log 约 4 万字符（1.3 万 token），glm-4-flash 上下文够放，
# 所以默认不截断；再大就该走 v0.2 的正则预筛，而不是硬塞
DEFAULT_MAX_CHARS = 50000

# 四问固定下来，避免每次问得不一样、结果没法比较
SYSTEM_PROMPT = (
    "你是做应急响应的安全工程师。只根据用户给的日志回答，不要补充日志里没有的信息。"
    "如果某项在日志里看不出来，就明确写「日志中无法判断」，不要猜。"
    "结论要给出依据：引用具体的行号或日志片段。"
)

USER_TEMPLATE = """下面是一份 Web 访问日志（Apache/Nginx 的 access 格式）。请按四个问题做初筛：

1. 谁在打：列出可疑来源 IP，按危险程度排序，并说明判断依据。
2. 什么时候：攻击集中的时间段。
3. 打哪里：被重点探测的路径，以及尝试了什么手法（注入/穿越/扫描/爆破等）。
4. 有没有得手：只看状态码和请求特征，指出最像「成功」的那几条，并说明为什么。

最后用一句话给出优先级建议（先查哪一条）。

日志如下：
---
{log}
---"""


def load_env(path=".env") -> None:
    """读 .env 到环境变量。

    故意不引第三方库：只认 KEY=VALUE，忽略空行和 # 注释。
    已经存在的环境变量不覆盖，方便临时用 shell 变量压过文件。
    """
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def read_log(path: str, max_chars: int):
    """读日志，返回 (文本, 是否截断, 总行数, 实际保留行数)。"""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    total = len(lines)
    text = "".join(lines)
    if max_chars and len(text) > max_chars:
        # 按行截断，别把一行的状态码切成两半
        kept, size = [], 0
        for line in lines:
            if size + len(line) > max_chars:
                break
            kept.append(line)
            size += len(line)
        return "".join(kept), True, total, len(kept)
    return text, False, total, total


def call_model(api_key: str, prompt: str, model: str, timeout: int = 90) -> dict:
    """发一次 chat/completions，返回解析后的 JSON。"""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,     # 分析类任务压低随机性
        "stream": False,
    }
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def explain_error(exc: Exception) -> str:
    """把 HTTP 错误翻译成「下一步该干什么」。"""
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 401:
            return "401 鉴权失败：API Key 抄错、带了空格，或者已被删除。重新复制一遍整串。"
        if exc.code == 429:
            return "429 触发限流或免费额度用尽：等一会儿再试，或换更小的日志。"
        if exc.code == 404:
            return "404 地址不对：确认用的是 https://open.bigmodel.cn/api/paas/v4/...，不是老的 v3。"
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return "HTTP %d：%s" % (exc.code, body or exc.reason)
    if isinstance(exc, urllib.error.URLError):
        return "连不上 open.bigmodel.cn：检查网络或代理。原始信息：%s" % exc.reason
    return "调用失败：%s" % exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="把访问日志交给 GLM 做应急初筛（四问）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("log", help="日志文件路径")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                        help="最多送多少字符给模型，默认 %d" % DEFAULT_MAX_CHARS)
    parser.add_argument("--model", default=os.environ.get("GLM_MODEL", DEFAULT_MODEL),
                        help="模型名，默认 %s" % DEFAULT_MODEL)
    parser.add_argument("--dry-run", action="store_true", help="只打印 prompt，不发请求")
    parser.add_argument("--json", dest="json_out", help="把原始响应另存为 JSON")
    args = parser.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if not os.path.isfile(args.log):
        print("[!] 日志不存在：%s" % args.log, file=sys.stderr)
        return 2

    log_text, truncated, total, kept = read_log(args.log, args.max_chars)
    print("[i] 读入 %s：%d 行，%d 字符%s"
          % (args.log, total, len(log_text),
             "（已截断，实际送入 %d 行）" % kept if truncated else ""))

    prompt = USER_TEMPLATE.format(log=log_text)

    if args.dry_run:
        print("-" * 60)
        print(prompt)
        print("-" * 60)
        print("[i] dry-run：没有发请求，不消耗额度")
        return 0

    load_env()
    api_key = os.environ.get("ZHIPU_API_KEY", "").strip()
    if not api_key:
        print("[!] 没有找到 ZHIPU_API_KEY", file=sys.stderr)
        print("    做法：cp .env.example .env，然后把 Key 填进 .env", file=sys.stderr)
        return 2

    print("[i] 调用 %s ..." % args.model)
    try:
        data = call_model(api_key, prompt, args.model)
    except Exception as exc:            # noqa: BLE001  这里就是要把各种网络错误都吃掉再翻译
        print("[!] " + explain_error(exc), file=sys.stderr)
        return 1

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print("[i] 原始响应已存到 %s" % args.json_out)

    try:
        answer = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        print("[!] 响应结构不对，原文：", file=sys.stderr)
        print(json.dumps(data, ensure_ascii=False)[:500], file=sys.stderr)
        return 1

    usage = data.get("usage") or {}
    print("-" * 60)
    print(answer.strip())
    print("-" * 60)
    if usage:
        print("[i] token 用量：输入 %s / 输出 %s"
              % (usage.get("prompt_tokens", "?"), usage.get("completion_tokens", "?")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
