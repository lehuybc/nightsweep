/* night-sweep web core: bech32, CBOR, blake2b, tx build/assemble. No dependencies, no secrets. */
(function (root) {
  'use strict';

  /* ---------- hex / bytes ---------- */
  const hexOf = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  function bytesOf(hex) {
    hex = String(hex).trim().toLowerCase();
    if (hex.length % 2 || /[^0-9a-f]/.test(hex)) throw new Error('hex không hợp lệ');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function concat(parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  /* ---------- bech32 ---------- */
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }
  function bech32Decode(str) {
    str = String(str).trim();
    if (str !== str.toLowerCase() && str !== str.toUpperCase()) throw new Error('chữ hoa/thường lẫn lộn');
    str = str.toLowerCase();
    const pos = str.lastIndexOf('1');
    if (pos < 1 || pos + 7 > str.length || str.length > 1023) throw new Error('độ dài/dấu phân cách sai');
    const hrp = str.slice(0, pos);
    const data = [];
    for (const ch of str.slice(pos + 1)) {
      const d = CHARSET.indexOf(ch);
      if (d < 0) throw new Error('ký tự lạ: ' + ch);
      data.push(d);
    }
    const hrpExp = [];
    for (const ch of hrp) hrpExp.push(ch.charCodeAt(0) >> 5);
    hrpExp.push(0);
    for (const ch of hrp) hrpExp.push(ch.charCodeAt(0) & 31);
    if (polymod(hrpExp.concat(data)) !== 1) throw new Error('sai checksum');
    const words = data.slice(0, -6);
    let acc = 0, bits = 0;
    const out = [];
    for (const w of words) {
      acc = (acc << 5) | w; bits += 5;
      while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); }
      acc &= (1 << bits) - 1;
    }
    if (bits >= 5 || acc) throw new Error('padding sai');
    return { hrp, bytes: Uint8Array.from(out) };
  }
  function bech32Encode(hrp, bytes) {
    const words = [];
    let acc = 0, bits = 0;
    for (const b of bytes) {
      acc = (acc << 8) | b; bits += 8;
      while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); }
      acc &= (1 << bits) - 1;
    }
    if (bits) words.push((acc << (5 - bits)) & 31);
    const hrpExp = [];
    for (const ch of hrp) hrpExp.push(ch.charCodeAt(0) >> 5);
    hrpExp.push(0);
    for (const ch of hrp) hrpExp.push(ch.charCodeAt(0) & 31);
    const pm = polymod(hrpExp.concat(words, [0, 0, 0, 0, 0, 0])) ^ 1;
    const chk = [];
    for (let i = 0; i < 6; i++) chk.push((pm >>> (5 * (5 - i))) & 31);
    return hrp + '1' + words.concat(chk).map((d) => CHARSET[d]).join('');
  }
  /** Địa chỉ mainnet Shelley. payKeyHash chỉ có khi phần payment là key hash (loại 0,2,4,6). */
  function parseMainnetAddress(str) {
    const { hrp, bytes } = bech32Decode(str);
    if (hrp !== 'addr') throw new Error('không phải địa chỉ mainnet (addr1…)');
    const type = bytes[0] >> 4, net = bytes[0] & 15;
    if (net !== 1) throw new Error('không phải mainnet');
    if (type > 7) throw new Error('kiểu địa chỉ không hỗ trợ');
    if (type <= 3 && bytes.length !== 57) throw new Error('độ dài địa chỉ sai');
    if ((type === 6 || type === 7) && bytes.length !== 29) throw new Error('độ dài địa chỉ sai');
    const keyPayment = type === 0 || type === 2 || type === 4 || type === 6;
    return { bytes, type, payKeyHash: keyPayment ? bytes.slice(1, 29) : null, raw: String(str).trim().toLowerCase() };
  }

  /* ---------- blake2b ---------- */
  const M64 = (1n << 64n) - 1n;
  const IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];
  const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;
  function blake2b(input, outlen) {
    outlen = outlen || 32;
    const h = IV.slice();
    h[0] ^= 0x01010000n ^ BigInt(outlen);
    let t = 0n;
    const blocks = Math.max(1, Math.ceil(input.length / 128));
    for (let b = 0; b < blocks; b++) {
      const last = b === blocks - 1;
      const chunk = new Uint8Array(128);
      const slice = input.subarray(b * 128, Math.min(input.length, (b + 1) * 128));
      chunk.set(slice);
      t += BigInt(slice.length);
      const m = [];
      for (let i = 0; i < 16; i++) {
        let w = 0n;
        for (let j = 7; j >= 0; j--) w = (w << 8n) | BigInt(chunk[i * 8 + j]);
        m.push(w);
      }
      const v = h.concat(IV);
      v[12] ^= t & M64; v[13] ^= (t >> 64n) & M64;
      if (last) v[14] ^= M64;
      const G = (a, bb, c, d, x, y) => {
        v[a] = (v[a] + v[bb] + x) & M64; v[d] = rotr(v[d] ^ v[a], 32);
        v[c] = (v[c] + v[d]) & M64; v[bb] = rotr(v[bb] ^ v[c], 24);
        v[a] = (v[a] + v[bb] + y) & M64; v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = (v[c] + v[d]) & M64; v[bb] = rotr(v[bb] ^ v[c], 63);
      };
      for (let r = 0; r < 12; r++) {
        const s = SIGMA[r % 10];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }
    const out = new Uint8Array(outlen);
    for (let i = 0; i < outlen; i++) out[i] = Number((h[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn);
    return out;
  }

  /* ---------- CBOR ---------- */
  class Tag { constructor(tag, value) { this.tag = tag; this.value = value; } }
  class CMap { constructor(entries) { this.entries = entries || []; } } // [[k,v],...] giữ thứ tự

  function head(major, n) {
    n = BigInt(n);
    if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
    if (n < 256n) return Uint8Array.of((major << 5) | 24, Number(n));
    if (n < 65536n) return Uint8Array.of((major << 5) | 25, Number(n >> 8n), Number(n & 255n));
    if (n < 4294967296n) {
      return Uint8Array.of((major << 5) | 26, Number((n >> 24n) & 255n), Number((n >> 16n) & 255n), Number((n >> 8n) & 255n), Number(n & 255n));
    }
    const out = new Uint8Array(9);
    out[0] = (major << 5) | 27;
    for (let i = 0; i < 8; i++) out[8 - i] = Number((n >> BigInt(8 * i)) & 255n);
    return out;
  }
  function enc(v) {
    if (v === true) return Uint8Array.of(0xf5);
    if (v === false) return Uint8Array.of(0xf4);
    if (v === null) return Uint8Array.of(0xf6);
    if (typeof v === 'number' || typeof v === 'bigint') {
      if (v < 0) throw new Error('số âm không dùng');
      return head(0, v);
    }
    if (v instanceof Uint8Array) return concat([head(2, v.length), v]);
    if (typeof v === 'string') { const b = new TextEncoder().encode(v); return concat([head(3, b.length), b]); }
    if (Array.isArray(v)) return concat([head(4, v.length)].concat(v.map(enc)));
    if (v instanceof CMap) {
      const parts = [head(5, v.entries.length)];
      for (const [k, val] of v.entries) { parts.push(enc(k)); parts.push(enc(val)); }
      return concat(parts);
    }
    if (v instanceof Tag) return concat([head(6, v.tag), enc(v.value)]);
    throw new Error('kiểu CBOR không hỗ trợ');
  }
  function decode(u8) {
    let p = 0;
    function rd() {
      if (p >= u8.length) throw new Error('CBOR cụt');
      const ib = u8[p++];
      const major = ib >> 5, ai = ib & 31;
      if (major === 7) {
        if (ai === 20) return false; if (ai === 21) return true; if (ai === 22 || ai === 23) return null;
        if (ai === 31) throw new Error('break lạc');
        throw new Error('simple/float không hỗ trợ');
      }
      let n;
      if (ai < 24) n = BigInt(ai);
      else if (ai === 24) n = BigInt(u8[p++]);
      else if (ai === 25) { n = BigInt((u8[p] << 8) | u8[p + 1]); p += 2; }
      else if (ai === 26) { n = (BigInt(u8[p]) << 24n) | (BigInt(u8[p + 1]) << 16n) | (BigInt(u8[p + 2]) << 8n) | BigInt(u8[p + 3]); p += 4; }
      else if (ai === 27) { n = 0n; for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(u8[p + i]); p += 8; }
      else if (ai === 31) n = -1n;
      else throw new Error('CBOR sai');
      const small = n >= 0n && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
      if (major === 0) return small;
      if (major === 1) return -1 - Number(n);
      if (major === 2 || major === 3) {
        if (n < 0n) { // chuỗi bất định
          const parts = [];
          while (u8[p] !== 0xff) parts.push(rd());
          p++;
          return major === 2 ? concat(parts) : parts.join('');
        }
        const b = u8.slice(p, p + Number(n)); p += Number(n);
        return major === 2 ? b : new TextDecoder().decode(b);
      }
      if (major === 4) {
        const out = [];
        if (n < 0n) { while (u8[p] !== 0xff) out.push(rd()); p++; } else for (let i = 0; i < Number(n); i++) out.push(rd());
        return out;
      }
      if (major === 5) {
        const entries = [];
        if (n < 0n) { while (u8[p] !== 0xff) entries.push([rd(), rd()]); p++; } else for (let i = 0; i < Number(n); i++) { const k = rd(); entries.push([k, rd()]); }
        return new CMap(entries);
      }
      if (major === 6) return new Tag(Number(n), rd());
      throw new Error('CBOR sai');
    }
    const v = rd();
    if (p !== u8.length) throw new Error('dư byte sau CBOR');
    return v;
  }

  /* ---------- giao dịch ---------- */
  const PARAMS = { minFeeA: 44, minFeeB: 155381, coinsPerUtxoByte: 4310, feeMargin: 1.05 };

  /** utxo: {tx_hash, tx_index, lovelace:number, assets:{"policyHex:nameHex": number}} */
  function totals(utxos) {
    let lovelace = 0n;
    const assets = new Map();
    for (const u of utxos) {
      lovelace += BigInt(u.lovelace);
      for (const [k, q] of Object.entries(u.assets || {})) assets.set(k, (assets.get(k) || 0n) + BigInt(q));
    }
    return { lovelace, assets };
  }
  function multiAssetCbor(assets) {
    const byPolicy = new Map();
    for (const [k, q] of assets) {
      const [p, n] = k.split(':');
      if (!byPolicy.has(p)) byPolicy.set(p, []);
      byPolicy.get(p).push([n || '', q]);
    }
    return new CMap(Array.from(byPolicy, ([p, arr]) => [bytesOf(p), new CMap(arr.map(([n, q]) => [bytesOf(n), q]))]));
  }
  function valueCbor(lovelace, assets) {
    return assets.size ? [lovelace, multiAssetCbor(assets)] : lovelace;
  }
  function outputLegacy(addrBytes, lovelace, assets) { return [addrBytes, valueCbor(lovelace, assets)]; }
  function minLovelace(addrBytes, assets) {
    // theo cách pycardano/ledger: kích thước output dạng "post-alonzo" (map), coin tính bằng 1 ADA
    const out = new CMap([[0, addrBytes], [1, valueCbor(1000000n, assets)]]);
    return BigInt((160 + enc(out).length) * PARAMS.coinsPerUtxoByte);
  }
  function bodyCbor(utxos, destBytes, fee, outLovelace, assets) {
    const inputs = utxos.map((u) => [bytesOf(u.tx_hash), u.tx_index]);
    return new CMap([[0, inputs], [1, [outputLegacy(destBytes, outLovelace, assets)]], [2, fee]]);
  }
  function witnessSetCbor(wits) { // wits: [[vkey(32), sig(64)], ...]
    return wits.length ? new CMap([[0, wits.map(([vk, sg]) => [vk, sg])]]) : new CMap([]);
  }
  function estimateTxSize(body, nSigners) {
    const dummy = [];
    for (let i = 0; i < nSigners; i++) dummy.push([new Uint8Array(32), new Uint8Array(64)]);
    return enc([body, witnessSetCbor(dummy), true, null]).length;
  }
  /** Dựng giao dịch gom về dest. Trả {bodyHex, txId, fee, outLovelace, minLovelace, size, ok, assets}. */
  function buildSweep(utxos, destAddr, nSigners) {
    const dest = parseMainnetAddress(destAddr).bytes;
    const t = totals(utxos);
    let fee = 400000n;
    let body, size;
    for (let i = 0; i < 6; i++) {
      body = bodyCbor(utxos, dest, fee, t.lovelace - fee, t.assets);
      size = estimateTxSize(body, nSigners);
      const next = BigInt(Math.floor((PARAMS.minFeeA * size + PARAMS.minFeeB) * PARAMS.feeMargin)) + 1n;
      if (next === fee) break;
      fee = next;
    }
    body = bodyCbor(utxos, dest, fee, t.lovelace - fee, t.assets);
    const bodyBytes = enc(body);
    const need = minLovelace(dest, t.assets);
    return {
      bodyHex: hexOf(bodyBytes), txId: hexOf(blake2b(bodyBytes, 32)), fee, size,
      outLovelace: t.lovelace - fee, minLovelace: need, ok: t.lovelace - fee >= need,
      assets: t.assets, inLovelace: t.lovelace,
    };
  }
  /** Lấy các cặp [vkey, sig] từ witness set mà ví trả về (hex). */
  function parseWitnessSet(hex) {
    const v = decode(bytesOf(hex));
    if (!(v instanceof CMap)) throw new Error('witness set không phải map');
    const out = [];
    for (const [k, val] of v.entries) {
      if (k === 0) {
        const arr = val instanceof Tag ? val.value : val;
        for (const w of arr) out.push([w[0], w[1]]);
      }
    }
    return out;
  }
  const vkeyHash = (vkey) => blake2b(vkey, 28);
  /** Ghép thân + chữ ký thành giao dịch hoàn chỉnh (hex). */
  function assemble(bodyHex, wits) {
    const body = decode(bytesOf(bodyHex));
    return hexOf(enc([body, witnessSetCbor(wits), true, null]));
  }
  /** Tách thông tin từ một giao dịch đầy đủ (kiểm tra). */
  function inspectTx(hex) {
    const v = decode(bytesOf(hex));
    return { body: v[0], wits: v[1], valid: v[2], aux: v[3] };
  }

  /* ---------- gom nhóm ---------- */
  /** wallets: [{address, label, account, utxos:[...]}] -> groups [{members:[...], utxos:[...]}] */
  function planGroups(wallets, opts) {
    const maxInputs = (opts && opts.maxInputs) || 60;
    const maxAccounts = (opts && opts.maxAccounts) || 10;
    const groups = [];
    let cur = { members: [], utxos: [] };
    for (const w of wallets) {
      const n = w.utxos.length;
      if (cur.members.length && (cur.utxos.length + n > maxInputs || cur.members.length >= maxAccounts)) {
        groups.push(cur); cur = { members: [], utxos: [] };
      }
      cur.members.push(w); cur.utxos = cur.utxos.concat(w.utxos);
    }
    if (cur.members.length) groups.push(cur);
    return groups;
  }
  function evaluateGroups(groups, dest) {
    for (const g of groups) {
      const b = buildSweep(g.utxos, dest, g.members.length);
      g.build = b;
    }
  }
  /** Gộp nhóm không đủ ADA vào nhóm bên cạnh nếu còn chỗ. */
  function fixGroups(groups, dest, maxInputs) {
    maxInputs = maxInputs || 60;
    evaluateGroups(groups, dest);
    let changed = true;
    while (changed) {
      changed = false;
      for (let i = 0; i < groups.length; i++) {
        if (groups[i].build.ok || groups.length < 2) continue;
        const j = i > 0 ? i - 1 : i + 1;
        const a = Math.min(i, j), b = Math.max(i, j);
        if (groups[a].utxos.length + groups[b].utxos.length > maxInputs) continue;
        const merged = { members: groups[a].members.concat(groups[b].members), utxos: groups[a].utxos.concat(groups[b].utxos) };
        merged.build = buildSweep(merged.utxos, dest, merged.members.length);
        groups.splice(a, 2, merged);
        changed = true;
        break;
      }
    }
    return groups;
  }

  const api = {
    hexOf, bytesOf, concat, bech32Decode, bech32Encode, parseMainnetAddress, blake2b, enc, decode, Tag, CMap,
    PARAMS, totals, minLovelace, buildSweep, parseWitnessSet, vkeyHash, assemble, inspectTx,
    planGroups, fixGroups, evaluateGroups,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.NightCore = api;
})(typeof self !== 'undefined' ? self : this);
