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


// IPv6 fragments: Fragment extension header is removed and payload is restored.
const ipv6Code = sliceBetween('function reassembleIpv6Fragments(list){', 'function ascii(d){');
const read32 = (d, o, little) => little ? (d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24) >>> 0 : (d[o] * 0x1000000 + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3]) >>> 0;
const ip6 = (d, o) => [...Array(8)].map((_, i) => ((d[o + 2*i] << 8) | d[o + 2*i + 1]).toString(16)).join(':');
const reassembleIp6 = new Function('u16', 'u32', 'ip6', 'parseFrame', ipv6Code + '; return reassembleIpv6Fragments')(
  read16, read32, ip6, parseFrame
);
function fragment6(no, offset, more, payload) {
  const raw = new Uint8Array(14 + 40 + 8 + payload.length);
  raw[12] = 0x86; raw[13] = 0xdd;
  raw[14] = 0x60; raw[18] = 0; raw[19] = 8 + payload.length; raw[20] = 44; raw[21] = 64;
  raw.set([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 22);
  raw.set([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 38);
  raw[54] = 17;
  const field = offset | (more ? 1 : 0);
  raw[56] = field >> 8; raw[57] = field & 255;
  raw[58] = 0x12; raw[59] = 0x34; raw[60] = 0; raw[61] = 0; raw[62] = 0; raw[63] = 7;
  raw.set(payload, 62);
  return { no, raw, linkType: 1, time: no, proto: 'IPv6 fragment', payload };
}
const first6 = fragment6(1, 0, true, Uint8Array.from({ length: 16 }, (_, i) => i));
const last6 = fragment6(2, 16, false, Uint8Array.from({ length: 8 }, (_, i) => i + 16));
const complete6 = reassembleIp6([last6, first6]);
assert.equal(complete6.length, 1);
assert.deepEqual(complete6[0].fragmentPackets, [1, 2]);
assert.equal(complete6[0].raw[20], 17);
assert.deepEqual([...complete6[0].raw.slice(54)], Array.from({ length: 24 }, (_, i) => i));
assert.equal(reassembleIp6([first6])[0].proto, 'IPv6 fragment');




const tcpHelper = sliceBetween('function reassembleTcpSegments(segments){', 'function buildRecoveries(){');
const sensitiveCode = sliceBetween('function collectSensitiveData(){', 'function peakTimeWindow(events,seconds,minCount){');
const collectFactory = new Function('packets', 'atob', 'TextDecoder', tcpHelper + sensitiveCode + '; return collectSensitiveData');
const testPackets = rows => rows.map(([no, seq, data]) => ({
  no, seq, proto: 'TCP', src: '10.0.0.1', sport: 12345, dst: '10.0.0.2', dport: 21,
  tcpSeq: seq, tcpFlags: 0, payload: byteText(data)
}));
let secrets = collectFactory(testPackets([
  [2, 108, 'ce\r\nPASS secret42\r\n'],
  [1, 100, 'USER ali']
]), atob, TextDecoder)();
assert(secrets.some(item => item.value === 'alice'));
assert(secrets.some(item => item.value === 'secret42'));
secrets = collectFactory(testPackets([
  [1, 100, 'USER alice\r\nPASS sec'],
  [2, 124, 'ret42\r\n']
]), atob, TextDecoder)();
assert(!secrets.some(item => item.value === 'secret42'));

const windowCode = sliceBetween('function peakTimeWindow(events,seconds,minCount){', 'function analyze(){');
const peakTimeWindow = new Function(windowCode + '; return peakTimeWindow')();
const burst = peakTimeWindow([
  { time: 4, key: 443, no: 4 }, { time: 1, key: 80, no: 1 },
  { time: 3, key: 53, no: 3 }, { time: 2, key: 80, no: 2 }
], 10, 3);
assert.equal(burst.count, 4);
assert.equal(burst.unique, 3);
assert.deepEqual(burst.packets, [1, 2, 3, 4]);
const separated = peakTimeWindow([
  { time: 0, key: 'a', no: 1 }, { time: 181, key: 'b', no: 2 }
], 180, 2);
assert.equal(separated.count, 0);



const synRatioCode = sliceBetween('function synCompletionRatio(synEvents,synackEvents,start,end){', 'function shannonEntropy(value){');
const synCompletionRatio = new Function(synRatioCode + '; return synCompletionRatio')();
const ratio = synCompletionRatio([
  { time: 1, flow: 'a', no: 1 }, { time: 2, flow: 'b', no: 2 }
], [
  { time: 3, flow: 'unrelated' }, { time: 3, flow: 'a' }
], 0, 10);
assert.equal(ratio.syn, 2);
assert.equal(ratio.ack, 1);
assert.equal(ratio.ratio, 0.5);

const qualityCode = sliceBetween('function shannonEntropy(value){', 'function analyze(){');
const { shannonEntropy, rapidMacSwitch } = new Function(qualityCode + '; return {shannonEntropy,rapidMacSwitch}')();
assert.equal(shannonEntropy('aaaaaaaa'), 0);
assert.equal(shannonEntropy('abcd'), 2);
assert.equal(rapidMacSwitch([
  { time: 0, mac: '00:11', no: 1 }, { time: 30, mac: '00:22', no: 2 }
], 60).length, 2);
assert.equal(rapidMacSwitch([
  { time: 0, mac: '00:11', no: 1 }, { time: 61, mac: '00:22', no: 2 }
], 60), null);
const weighted = peakTimeWindow([
  { time: 1, key: 'dns-a', no: 1, length: 20, entropy: 3.8, long: true, bytes: 100 },
  { time: 2, key: 'dns-b', no: 2, length: 30, entropy: 4.2, long: true, bytes: 200 }
], 10, 2);
assert.equal(weighted.avgLength, 25);
assert.equal(weighted.avgEntropy, 4);
assert.equal(weighted.longCount, 2);
assert.equal(weighted.sumBytes, 300);

const shaCode = sliceBetween('async function sha256Hex(data){', 'function makeReport(){');
const sha256Hex = new Function(shaCode + '; return sha256Hex')();
assert.equal(await sha256Hex(new TextEncoder().encode('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');


const analyzeCode = sliceBetween('function analyze(){', 'function signature(b){');
const analysisFactory = new Function(
  'packets','fmtBytes','isPrivate','peakTimeWindow','shannonEntropy','rapidMacSwitch',
  'synCompletionRatio','buildRecoveries','collectSensitiveData',
  'let conversations=[],domains=[],findings=[],artifacts=[],recoveries=[],sensitiveData=[];' +
  analyzeCode + '; return () => { analyze(); return {findings,domains,conversations}; }'
);
const runAnalysis = packets => analysisFactory(
  packets, value => String(value),
  ip => /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/.test(ip),
  peakTimeWindow, shannonEntropy, rapidMacSwitch, synCompletionRatio,
  () => [], () => []
)();
const packet = (no, fields) => ({
  no, time: no, src: '10.0.0.1', dst: '8.8.8.8', sport: 40000+no, dport: 443,
  proto: 'TCP', tcpFlags: 0, tcpSeq: no*100, payload: new Uint8Array(),
  length: 100, app: '', dns: [], ...fields
});
const portBurst = Array.from({length:24},(_,i)=>packet(i+1,{time:i/2,dport:1000+i,tcpFlags:2}));
assert(runAnalysis(portBurst).findings.some(f => f.title.includes('quét nhiều cổng')));
const portDrip = Array.from({length:24},(_,i)=>packet(i+1,{time:i*20,dport:1000+i,tcpFlags:2}));
assert(!runAnalysis(portDrip).findings.some(f => f.title.includes('quét nhiều cổng')));
const synBurst = [];
for(let i=0;i<100;i++) synBurst.push(packet(i+1,{
  time:i/20,src:'10.1.'+Math.floor(i/250)+'.'+(i%250+1),sport:40000+i,dst:'10.0.0.9',
  dport:80,tcpFlags:2
}));
for(let i=0;i<10;i++) synBurst.push(packet(101+i,{
  time:1+i/20,src:'10.0.0.9',sport:80,dst:'10.1.'+Math.floor(i/250)+'.'+(i%250+1),
  dport:40000+i,tcpFlags:18
}));
assert(runAnalysis(synBurst).findings.some(f => f.title.includes('SYN flood')));
const tunnelPackets=[];
let seed=123456;
for(let i=0;i<14;i++){
  let label='';
  for(let j=0;j<24;j++){seed=(seed*1664525+1013904223)>>>0;label+='abcdefghijklmnopqrstuvwxyz234567'[seed&31]}
  tunnelPackets.push(packet(i+1,{proto:'UDP',sport:53000,dport:53,time:i*2,tcpFlags:null,
    dns:[{name:label+'.example.com',type:'A',response:false,record:false}]}));
}
assert(runAnalysis(tunnelPackets).findings.some(f => f.title.includes('DNS')&&f.title.includes('tunnel')));
const arpRapid=[
  packet(1,{proto:'ARP',time:1,arp:{srcIp:'10.0.0.5',srcMac:'00:11'} }),
  packet(2,{proto:'ARP',time:2,arp:{srcIp:'10.0.0.5',srcMac:'00:22'} })
];
assert(runAnalysis(arpRapid).findings.some(f => f.title.includes('đổi MAC')));
const arpSlow=[
  packet(1,{proto:'ARP',time:1,arp:{srcIp:'10.0.0.5',srcMac:'00:11'} }),
  packet(2,{proto:'ARP',time:120,arp:{srcIp:'10.0.0.5',srcMac:'00:22'} })
];
assert(!runAnalysis(arpSlow).findings.some(f => f.title.includes('đổi MAC')));
const exfilBurst=Array.from({length:10},(_,i)=>packet(i+1,{
  time:i*2,src:'10.0.0.4',dst:'1.1.1.1',length:260000
}));
assert(runAnalysis(exfilBurst).findings.some(f => f.title.includes('outbound lớn')));

console.log('PASS: end-to-end detection rules, SYN tuple matching, TCP secret reassembly, SHA-256, sliding windows, DNS entropy and ARP timing, syntax, TCP reorder/retransmit/gap/conflict, multiple HTTP responses, IPv4 and IPv6 complete/incomplete fragments');
