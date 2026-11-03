from detect import detect_attacks
with open("test_logs.txt") as f: alerts, ts = detect_attacks(f.read())
for a in alerts: print(a["id"], a["da"], a["en"], a["ai"])
