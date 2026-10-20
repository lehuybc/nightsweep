// Proxy tối thiểu cho NIGHT Sweep trên Cloudflare Pages Functions.
// Chỉ cho phép đúng 3 lời gọi: lịch thaw Midnight (GET), Koios address_utxos và submittx (POST).
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0';
const json = (code, obj, extra = {}) => new Response(JSON.stringify(obj), {
  status: code,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra },
});

export async function onRequest({ request }) {
  const sfs = request.headers.get('Sec-Fetch-Site');
  if (sfs && sfs !== 'same-origin' && sfs !== 'none') return json(403, { error: 'không cùng nguồn' });

  const q = new URL(request.url).searchParams;
  const t = q.get('t');
  let url, init;

  if (t === 'midnight') {
    if (request.method !== 'GET') return json(405, { error: 'chỉ GET' });
    const a = q.get('a') || '';
    if (!/^addr1[0-9a-z]{50,120}$/.test(a)) return json(400, { error: 'địa chỉ sai' });
    url = 'https://mainnet.prod.gd.midnighttge.io/thaws/' + a + '/schedule';
    init = { method: 'GET', headers: { Accept: 'application/json', 'User-Agent': UA } };
  } else if (t === 'koios') {
    if (request.method !== 'POST') return json(405, { error: 'chỉ POST' });
    const p = q.get('p');
    if (p !== '/address_utxos' && p !== '/submittx') return json(400, { error: 'đường dẫn không được phép' });
    const len = Number(request.headers.get('Content-Length') || 0);
    if (len > 65536) return json(413, { error: 'quá lớn' });
    const body = await request.arrayBuffer();
    if (body.byteLength === 0) return json(400, { error: 'thiếu nội dung' });
    if (body.byteLength > 65536) return json(413, { error: 'quá lớn' });
    url = 'https://api.koios.rest/api/v1' + p;
    init = { method: 'POST', body, headers: { Accept: 'application/json', 'User-Agent': UA, 'Content-Type': p === '/submittx' ? 'application/cbor' : 'application/json' } };
  } else {
    return json(400, { error: 'thiếu tham số t' });
  }

  try {
    const r = await fetch(url, { ...init, redirect: 'manual' });
    return new Response(r.body, {
      status: r.status,
      headers: { 'Content-Type': r.headers.get('content-type') || 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
    });
  } catch (e) {
    return json(502, { error: 'không gọi được máy chủ gốc' });
  }
}
