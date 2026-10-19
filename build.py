#!/usr/bin/env python3
"""Reproducible build: src/app.template.html + src/core.js -> public/index.html.
Also prints the SHA-256 of index.html and the CSP hashes of its inline scripts."""
import base64, hashlib, re, pathlib
root = pathlib.Path(__file__).resolve().parent
core = (root / "src/core.js").read_text(encoding="utf-8")
tpl = (root / "src/app.template.html").read_text(encoding="utf-8")
assert "/*__CORE__*/" in tpl
html = tpl.replace("/*__CORE__*/", core.replace("</script", "<\\/script"))
out = root / "public/index.html"
out.write_bytes(html.encode("utf-8"))
print("index.html sha256:", hashlib.sha256(out.read_bytes()).hexdigest())
for s in re.findall(r"<script>([\s\S]*?)</script>", html):
    print("CSP script-src hash: 'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode())
