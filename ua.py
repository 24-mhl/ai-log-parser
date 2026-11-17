LOG = r"C:\Users\麓山阁\Desktop\CTF环境\应急靶场\access.log"

counts = {}

with open(LOG, encoding="utf-8", errors="replace") as f:
    for line in f:
        parts = line.split('"')
        if len(parts) < 6:
            continue
        ua = parts[5]
        counts[ua] = counts.get(ua, 0) + 1

for ua, n in sorted(counts.items(), key=lambda kv: -kv[1]):
    print("%4d  %s" % (n, ua[:70]))
