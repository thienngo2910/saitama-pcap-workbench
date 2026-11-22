import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const html = await readFile(join(root, 'index.html'), 'utf8');
const scriptStart = html.indexOf('<script>');
const scriptEnd = html.indexOf('</script>', scriptStart);
assert(scriptStart >= 0 && scriptEnd > scriptStart, 'index.html contains the application script');
new Function(html.slice(scriptStart + 8, scriptEnd));

function sliceBetween(start, end) {
  const a = html.indexOf(start);
  const b = html.indexOf(end, a + start.length);
  assert(a >= 0 && b > a, `source section found: ${start}`);
  return html.slice(a, b);
}
const byteText = value => Uint8Array.from([...value].map(ch => ch.charCodeAt(0)));
const joinBytes = parts => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

// TCP sequence reconstruction: reorder, retransmit, gap, and overlapping conflict.
const tcpCode = sliceBetween('function reassembleTcpSegments(segments){', 'function addTcpPacketToSessions');
const reassembleTcp = new Function(tcpCode + '; return reassembleTcpSegments')();
let tcp = reassembleTcp([
  { no: 2, seq: 103, flags: 0, data: byteText('def') },
  { no: 1, seq: 100, flags: 0, data: byteText('abc') },
  { no: 3, seq: 100, flags: 0, data: byteText('abc') }
]);
assert.equal(new TextDecoder().decode(tcp.bytes), 'abcdef');
assert.equal(tcp.gapBytes, 0);
tcp = reassembleTcp([
  { no: 1, seq: 10, flags: 0, data: byteText('abc') },
  { no: 2, seq: 15, flags: 0, data: byteText('f') }
]);
assert.equal(tcp.gapBytes, 2);
tcp = reassembleTcp([
  { no: 1, seq: 10, flags: 0, data: byteText('abcd') },
  { no: 2, seq: 12, flags: 0, data: byteText('XX') }
]);
assert.equal(tcp.conflictBytes, 2);
assert.equal(new TextDecoder().decode(tcp.bytes), 'abcd');

// HTTP keep-alive: more than one response, both content-length and chunked.
const httpCode = sliceBetween('function httpByteText(bytes){', 'function addRecovery');
const extractHttp = new Function('joinBytes', httpCode + '; return extractHttpObjects')(joinBytes);
const body1 = 'A'.repeat(70);
const body2 = 'B'.repeat(80);
const stream = byteText(
  'HTTP/1.1 200 OK\r\nContent-Length: 70\r\nContent-Disposition: attachment; filename=one.bin\r\n\r\n' +
  body1 +
  'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n50\r\n' +
  body2 + '\r\n0\r\n\r\n'
);
const objects = extractHttp(stream);
assert.equal(objects.length, 2);
assert.equal(objects[0].name, 'one.bin');
assert.equal(objects[0].body.length, 70);
assert.equal(objects[1].body.length, 80);
assert.equal(extractHttp(byteText('HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nshort')).length, 0);

// IPv4 fragment assembly using reversed arrival order and incomplete datagram.
const ipCode = sliceBetween('function reassembleIpv4Fragments(list){', 'function ascii(d){');
const read16 = (d, o, little) => little ? d[o] | d[o + 1] << 8 : d[o] << 8 | d[o + 1];
const ipv4 = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
const parseFrame = (raw, linkType, no) => ({
  no, proto: 'UDP', raw, linkType, payload: raw.slice(34),
  src: '10.0.0.1', dst: '10.0.0.2'
});
const reassembleIp = new Function('u16', 'ip4', 'parseFrame', ipCode + '; return reassembleIpv4Fragments')(
  read16, ipv4, parseFrame
);
function fragment(no, offset, more, payload) {
  const raw = new Uint8Array(14 + 20 + payload.length);
  raw[12] = 8; raw[13] = 0;
  raw[14] = 0x45; raw[17] = 20 + payload.length;
  raw[18] = 0x12; raw[19] = 0x34;
  const flags = (more ? 0x2000 : 0) | offset / 8;
  raw[20] = flags >> 8; raw[21] = flags & 255;
  raw[22] = 64; raw[23] = 17;
  raw.set([10, 0, 0, 1], 26); raw.set([10, 0, 0, 2], 30);
  raw.set(payload, 34);
  return { no, raw, linkType: 1, time: no, proto: 'UDP', payload };
}
const first = fragment(1, 0, true, Uint8Array.from({ length: 16 }, (_, i) => i));
const last = fragment(2, 16, false, Uint8Array.from({ length: 8 }, (_, i) => i + 16));
const complete = reassembleIp([last, first]);
assert.equal(complete.length, 1);
assert.equal(complete[0].proto, 'UDP');
assert.deepEqual(complete[0].fragmentPackets, [1, 2]);
assert.equal(complete[0].raw.length, 58);
assert.deepEqual([...complete[0].raw.slice(34)], Array.from({ length: 24 }, (_, i) => i));
assert.equal(reassembleIp([first])[0].proto, 'IPv4 fragment');

console.log('PASS: script syntax, TCP reorder/retransmit/gap/conflict, multiple HTTP responses, IPv4 complete/incomplete fragments');
