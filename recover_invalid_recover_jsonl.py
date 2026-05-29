
import json, os, tempfile

src = "signatures.jsonl"
bad_path = "signatures.invalid.jsonl"

fd, tmp_path = tempfile.mkstemp(prefix="signatures.valid.", suffix=".jsonl", dir=".")
os.close(fd)

ok = bad = 0
with open(src, "r", encoding="utf-8") as fin, \
     open(tmp_path, "w", encoding="utf-8") as fout_ok, \
     open(bad_path, "w", encoding="utf-8") as fout_bad:
    for ln, line in enumerate(fin, 1):
        raw = line.rstrip("\n")
        if not raw.strip():
            continue
        try:
            json.loads(raw)
            fout_ok.write(raw + "\n")
            ok += 1
        except Exception as e:
            fout_bad.write(json.dumps({
                "line_no": ln,
                "raw": raw,
                "error": str(e),
            }, ensure_ascii=False) + "\n")
            bad += 1

os.replace(tmp_path, src)
print(f"done: valid={ok} invalid={bad}")