#!/usr/bin/env node
// Turns the three raw IANA CSVs into ipv6-data.js. Invoked by update-ipv6-data.sh —
// not meant to be run with hand-picked args.
'use strict';
const fs = require('fs');

const [, , topPath, unicastPath, specialPath, topDate, unicastDate, specialDate] = process.argv;
if (!specialDate) {
  console.error('usage: build-ipv6-data.js <top.csv> <unicast.csv> <special.csv> <topDate> <unicastDate> <specialDate>');
  process.exit(1);
}

function parseCSV(text) {
  const rows = []; let field = '', row = [], inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false; }
      else field += c;
    } else {
      if (c === '"') inQuotes = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
      else if (c === '\r') { /* skip */ }
      else field += c;
    }
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows.filter(r => r.length > 1 && r[0] && r[0].trim() !== '');
}

function cleanFootnote(s) { return (s || '').replace(/\s*\[\d+\]/g, '').trim(); }
function cleanNote(s) {
  if (!s) return '';
  // CSV soft-wraps long notes across lines mid-sentence; collapse those first,
  // then break onto a new line after each sentence-ending period for readability.
  const collapsed = s.replace(/\s*\n\s*/g, ' ').trim();
  return collapsed.replace(/\.\s+(?=[^a-z\s])/g, '.\n');
}
function extractRfcs(cell) {
  const matches = [...(cell || '').matchAll(/\[([^\]]+)\]/g)].map(m => m[1].trim());
  return matches.length ? matches.join(', ') : (cell || '').trim();
}
function jsStr(s) { return JSON.stringify(s == null ? '' : String(s)); }
function fmtEntries(list, fields) {
  return list.map(e => '  {' + fields.map(f => `${f}:${jsStr(e[f])}`).join(', ') + '}').join(',\n');
}

const topRaw = parseCSV(fs.readFileSync(topPath, 'utf8')).slice(1)
  .map(r => ({ prefix: r[0], allocation: r[1] || 'Reserved by IETF', note: cleanNote(r[3]) }));
const unicastRaw = parseCSV(fs.readFileSync(unicastPath, 'utf8')).slice(1)
  .map(r => ({ prefix: r[0], designation: r[1], date: r[2], status: r[5], note: cleanNote(r[6]) }));
const specialRaw = parseCSV(fs.readFileSync(specialPath, 'utf8')).slice(1)
  .map(r => ({ prefix: cleanFootnote(r[0]), name: (r[1] || '').trim(), rfc: extractRfcs(r[2]), date: (r[3] || '').trim(), term: (r[4] || '').trim() }));

if (topRaw.length < 10) throw new Error(`top registry: unexpected row count ${topRaw.length}`);
if (unicastRaw.length < 10) throw new Error(`unicast registry: unexpected row count ${unicastRaw.length}`);
if (specialRaw.length < 10) throw new Error(`special registry: unexpected row count ${specialRaw.length}`);

const out = `/* IANA IPv6 registry data for ipv6-address-map.html
 * Regenerate with: scripts/update-ipv6-data.sh
 */

/* IPv6 Address Space registry — Last Updated ${topDate} */
const TOP_RAW = [
${fmtEntries(topRaw, ['prefix', 'allocation', 'note'])}
];

/* IPv6 Global Unicast Address Assignments registry — Last Updated ${unicastDate} */
const UNICAST_RAW = [
${fmtEntries(unicastRaw, ['prefix', 'designation', 'date', 'status', 'note'])}
];

/* IANA IPv6 Special-Purpose Address Registry — Last Updated ${specialDate} */
/* Sparse, nested annotations — not a partition of the space, so these are looked up */
/* against whichever tile is selected rather than drawn as tiles of their own. */
const SPECIAL_RAW = [
${fmtEntries(specialRaw, ['prefix', 'name', 'rfc', 'date', 'term'])}
];

const LAST_UPDATED = { top:${jsStr(topDate)}, unicast:${jsStr(unicastDate)}, special:${jsStr(specialDate)} };
`;

process.stdout.write(out);
