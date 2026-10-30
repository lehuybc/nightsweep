# Verify that the site is the code you can read

1. Get the source and build: `python3 build.py` prints the SHA-256 of `public/index.html`.
2. Download what the site serves and hash it:
   ```
   curl -s https://nightsweep.xyz/ | sha256sum
   ```
3. The two hashes should be identical. If they differ, do not use the site and tell the maintainer.

Notes
- If you put the site behind Cloudflare, switch **off** Auto Minify, Rocket Loader and Email Obfuscation. They rewrite the page, change its hash and break the CSP script hashes.
- Release checksums for `og.png` and `favicon.svg` are in `SHA256SUMS`.
- You can also open `public/index.html` from your own disk (file://) — the "official host" warning is not shown for local files, and the page works the same.
- Read the diff before trusting an update: the whole UI/logic is in `src/app.template.html`, transaction building in `src/core.js`.
