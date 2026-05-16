
/* ── PARSE-X · Artifact Extraction Engine ─────────────────────────────────── */

const _IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:3[0-2]|[12]\d|\d))?\b/g;

const _IPV6 = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}/g;

function defangAll(raw) {
  return raw
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.')
    .replace(/\[dot\]/gi, '.').replace(/\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[at\]/gi, '@')
    .replace(/\(at\)/gi, '@');
}

function parseArtifacts(rawInput) {
  const text = defangAll(rawInput);
  const seen = new Set();
  const artifacts = [];
  let uid = 0;

  function add(type, label, group, value) {
    const key = `${type}::${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    artifacts.push({ id: ++uid, type, label, group, value });
  }

  /* 1. Hashes — longest first to avoid SHA512 matching as SHA256 fragment */
  for (const [src, type, label] of [
    [/\b[0-9a-fA-F]{128}\b/g, 'hash_sha512', 'SHA-512'],
    [/\b[0-9a-fA-F]{64}\b/g,  'hash_sha256', 'SHA-256'],
    [/\b[0-9a-fA-F]{40}\b/g,  'hash_sha1',   'SHA-1'],
    [/\b[0-9a-fA-F]{32}\b/g,  'hash_md5',    'MD5'],
  ]) {
    for (const m of text.matchAll(new RegExp(src.source, 'g')))
      add(type, label, 'hash', m[0].toLowerCase());
  }

  /* 2. CVE IDs */
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi))
    add('cve', 'CVE', 'threat', m[0].toUpperCase());

  /* 3. MITRE ATT&CK techniques */
  for (const m of text.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g))
    add('mitre', 'ATT&CK', 'threat', m[0]);

  /* 4. Registry keys */
  for (const m of text.matchAll(/\b(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s"'<>|,;\n]+/gi))
    add('registry', 'Registry', 'host', m[0]);

  /* 5. Windows paths — drive letter or env var prefix */
  for (const m of text.matchAll(/(?:[a-zA-Z]:\\|%[a-zA-Z_][a-zA-Z0-9_]*%\\)[^\s"'<>|,;\n]+/g)) {
    const v = m[0].replace(/[\\.,;!?)\]>]+$/, '');
    add('winpath', 'Win Path', 'host', v);
  }

  /* 6. URLs */
  for (const m of text.matchAll(/https?:\/\/[^\s"'<>\[\]{}|\\^`\n]+/gi)) {
    const v = m[0].replace(/[.,;:!?)\]>]+$/, '');
    add('url', 'URL', 'network', v);
  }

  /* 7. Email addresses */
  for (const m of text.matchAll(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}\b/gi))
    add('email', 'Email', 'network', m[0].toLowerCase());

  /* 8. IPv4 */
  for (const m of text.matchAll(new RegExp(_IPV4.source, 'g')))
    add('ip', 'IPv4', 'network', m[0]);

  /* 9. IPv6 */
  for (const m of text.matchAll(new RegExp(_IPV6.source, 'g'))) {
    const v = m[0];
    if (v.includes(':') && v.length > 6) add('ipv6', 'IPv6', 'network', v);
  }

  /* 10. MAC addresses */
  for (const m of text.matchAll(/\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/g))
    add('mac', 'MAC', 'network', m[0].toLowerCase());

  /* 11. Ports — explicit "port NNN" and ":PORT" not in timestamps */
  for (const m of text.matchAll(/\bports?\s+(\d{1,5})\b/gi)) {
    const p = parseInt(m[1], 10);
    if (p >= 1 && p <= 65535) add('port', 'Port', 'network', m[1]);
  }
  /* :PORT where preceding char is not a digit (avoids HH:MM:SS) */
  for (const m of text.matchAll(/(?<!\d):(\d{1,5})\b/g)) {
    const p = parseInt(m[1], 10);
    if (p >= 1 && p <= 65535) add('port', 'Port', 'network', m[1]);
  }

  /* 12. Process names (.exe, .bat, .cmd, .ps1, .vbs, .hta, .msi, .scr, .pif) */
  for (const m of text.matchAll(/\b[\w][\w\-. ]{0,60}\.(exe|bat|cmd|ps1|vbs|hta|msi|scr|pif)\b/gi)) {
    const v = m[0].toLowerCase();
    if (!seen.has(`url::${v}`) && !seen.has(`winpath::${v}`))
      add('process', 'Process', 'host', v);
  }

  /* 13. DLLs and drivers (.dll, .sys) */
  for (const m of text.matchAll(/\b[\w][\w\-. ]{0,60}\.(dll|sys)\b/gi)) {
    const v = m[0].toLowerCase();
    if (!seen.has(`url::${v}`) && !seen.has(`winpath::${v}`))
      add('dll', 'DLL/Driver', 'host', v);
  }

  /* 14. Unix paths */
  for (const m of text.matchAll(/\/(?:etc|tmp|var|usr|home|bin|sbin|opt|proc|sys|dev|root|boot|lib)(?:\/[\w.\-]+)+/g))
    add('unixpath', 'Unix Path', 'host', m[0]);

  /* 15. Domains — after IPs/URLs so numeric-only dotted strings stay as IPs */
  const domainRe = /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
  for (const m of text.matchAll(domainRe)) {
    const v = m[0].toLowerCase();
    if (seen.has(`ip::${v}`) || seen.has(`email::${v}`)) continue;
    /* skip if it's inside an already-extracted URL */
    const inUrl = [...seen].some(k => k.startsWith('url::') && k.slice(5).includes(v));
    if (inUrl) continue;
    const parts = v.split('.');
    /* skip version strings like 1.2.3.4 or 10.0.0 */
    if (parts.slice(0, -1).every(l => /^\d+$/.test(l))) continue;
    add('domain', 'Domain', 'network', v);
  }

  return artifacts;
}

function getTypeCounts(artifacts) {
  const counts = {};
  for (const a of artifacts) counts[a.type] = (counts[a.type] || 0) + 1;
  return counts;
}

const TYPE_LABELS = {
  ip: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  email: 'Email', mac: 'MAC', port: 'Port',
  hash_md5: 'MD5', hash_sha1: 'SHA-1', hash_sha256: 'SHA-256', hash_sha512: 'SHA-512',
  registry: 'Registry', winpath: 'Win Path', unixpath: 'Unix Path',
  process: 'Process', dll: 'DLL/Driver', cve: 'CVE', mitre: 'ATT&CK',
};

const GROUP_TYPES = {
  network: ['ip', 'ipv6', 'domain', 'url', 'email', 'mac', 'port'],
  hash:    ['hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512'],
  host:    ['registry', 'winpath', 'unixpath', 'process', 'dll'],
  threat:  ['cve', 'mitre'],
};

function parseRealtime() {
  const raw = document.getElementById('px-input')?.value || '';
  const artifacts = parseArtifacts(raw);
  const total = artifacts.length;
  const infoEl = document.getElementById('parsed-info');
  const btnEl  = document.getElementById('extract-btn');

  if (total === 0) {
    if (infoEl) infoEl.innerHTML = '';
    if (btnEl) btnEl.disabled = true;
    return;
  }

  const counts = getTypeCounts(artifacts);
  const parts = [`<span>${total}</span> artifact${total > 1 ? 's' : ''}`];
  const summary = [];
  for (const [t, c] of Object.entries(counts))
    summary.push(`${c} ${TYPE_LABELS[t] || t}`);
  if (summary.length) parts.push(summary.join(' · '));

  if (infoEl) infoEl.innerHTML = parts.join(' · ');
  if (btnEl) btnEl.disabled = false;
}
