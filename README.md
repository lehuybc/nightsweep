# NIGHT Sweep

Check Midnight NIGHT (Glacier Drop / Scavenger Mine) thaw schedules across many Cardano addresses, and sweep NIGHT from many addresses into one. **Your wallet (Typhon, CIP-30) signs; the page has no seed-phrase or private-key field and never sees your keys.**

Live site: https://nightsweep.xyz/  ·  Redeeming itself is still done manually on https://redeem.midnight.gd/.

## Why you can trust it
- **Open source (MIT)**: the whole page is one readable file built from `src/`.
- **No keys**: signing happens in your wallet; the page only receives signatures. It warns if you paste something that looks like a seed phrase.
- **Strict CSP**: the page can only talk to its own origin; it cannot load third-party scripts (see `server/php/htaccess.txt` / `server/nginx/nightsweep.conf`).
- **Verifiable build**: `python3 build.py` reproduces `public/index.html` byte for byte. Compare with the deployed page — see [docs/VERIFY.md](docs/VERIFY.md).
- **Anonymous counters only** (optional): event names, no addresses, no cookies, no raw IPs (`server/php/track.php`).
- **Official host check**: copies served from another domain show a full-screen "not the official site" warning.

## Layout
```
src/            app.template.html (UI + logic), core.js (transaction building, pure JS)
public/         built index.html, og.png, favicon.svg, config.example.js
server/php/     proxy.php (allow-listed proxy), track.php, dashboard.php, htaccess.txt (Apache)
server/nginx/   nightsweep.conf (same rules for nginx, which ignores .htaccess)
build.py        reproducible build + hashes
```

## Build & deploy
1. `python3 build.py` → `public/index.html`; note the printed CSP hashes and put them in your CSP (`htaccess.txt` on Apache, `nightsweep.conf` on nginx).
2. Copy `public/config.example.js` to `public/config.js` and adjust.
3. Deploy `public/` plus `server/php/` (Apache or nginx with PHP-FPM; on nginx install `server/nginx/nightsweep.conf`, since `.htaccess` is ignored there). The proxy is required: the Midnight API sits behind a WAF and does not allow direct browser calls.
4. Change the donation addresses in `src/app.template.html` (`DONATE`) to your own, or remove that block.

## Security
See [SECURITY.md](SECURITY.md). Never enter a seed phrase into any website, including this one.

## Disclaimer
Software is provided as is. Always verify the destination address (first and last characters) before signing, and test with a small amount first.
