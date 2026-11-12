import sys

# 默认路径是指定的靶场样本；换日志时直接 `python stats.py 别的.log`
LOG = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\麓山阁\Desktop\CTF环境\应急靶场\access.log"

counts = {}

with open(LOG, encoding="utf-8", errors="replace") as f:
    for line in f:
        parts = line.split()
        if len(parts) < 9:
            continue
        ip = parts[0]
        status = parts[8]
        counts[ip] = counts.get(ip, {})
        counts[ip][status] = counts[ip].get(status, 0) + 1

for ip in sorted(counts):
    d = counts[ip]
    fails = d.get("401", 0) + d.get("403", 0)
    wins = d.get("302", 0) + d.get("200", 0)

    if fails > 0 and wins > 0:
        tag = "失败后成功"
    elif fails > 0:
        tag = "零得手"
    else:
        tag = "正常业务"

    print("%-16s %-12s %s" % (ip, tag, d))


