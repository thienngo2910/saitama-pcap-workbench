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
const httpTools = new Function('joinBytes', httpCode + '; return {extractHttpObjects,httpPathFilename,extractMultipartFiles}')(joinBytes);
const extractHttp = httpTools.extractHttpObjects;
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
const upload = byteText('POST /upload HTTP/1.1\r\nHost: lab.local\r\nContent-Length: 70\r\n\r\n' + body1);
const uploaded = extractHttp(upload);
assert.equal(uploaded.length, 1);
assert.equal(uploaded[0].method, 'POST');
assert.equal(uploaded[0].path, '/upload');
assert.equal(uploaded[0].body.length, 70);
const partial=extractHttp(byteText('HTTP/1.1 200 OK\r\nContent-Length: 500\r\nContent-Type: application/octet-stream\r\n\r\nshort'));
assert.equal(partial.length,1,'salvage a truncated HTTP body as an explicitly partial candidate');
assert.equal(partial[0].truncated,true);
assert.equal(partial[0].body.length,5);
assert.equal(partial[0].contentType,'application/octet-stream');
const shortObject=extractHttp(byteText('HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Disposition: attachment; filename*=UTF-8\'\'file%20one.ps1\r\n\r\nabcd'));
assert.equal(shortObject.length,1,'do not discard small HTTP objects');
assert.equal(shortObject[0].name,'file one.ps1');
const manyHttp=byteText(Array.from({length:20},(_,i)=>'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Disposition: attachment; filename="object-'+i+'.ps1"\r\n\r\nabc').join(''));
assert.equal(extractHttp(manyHttp).length,20,'extract more than twelve objects from a persistent connection');



const assessmentCode = sliceBetween('function scanRecoveredFile(name,kind,bytes,sig){', 'function findMagicOffset(b){');
const scanRecoveredFile = new Function(assessmentCode + '; return scanRecoveredFile')();
const recoveryCode = sliceBetween('function recoveryPriority(kind,name){', 'function decodeB32(s){');
const savedHttpObjects=[];
const addRecoveryTest = new Function('recoveries','signature','scanRecoveredFile',recoveryCode+'; return addRecovery')(
  savedHttpObjects, bytes => ({label:'Unknown binary data', ext:'bin'}), scanRecoveredFile
);
for (let i=0;i<100;i++) addRecoveryTest(savedHttpObjects, 'dns-'+i+'.bin', 'DNS decoded · base64url', Uint8Array.of(i+100), [i+1], 'Low priority candidate');
for (let i=0;i<16;i++) addRecoveryTest(savedHttpObjects, 'checking.ps1', 'HTTP response object · application/octet-stream', Uint8Array.of(i+1), [4221+i], 'Complete capture');
assert.equal(savedHttpObjects.length,100,'keep recovery memory bounded');
assert.equal(savedHttpObjects.filter(x=>x.kind.startsWith('HTTP response object')).length,16,'keep HTTP objects even when earlier DNS results fill the candidate list');
assert.equal(savedHttpObjects.find(x=>x.kind.startsWith('HTTP response object')).name,'checking.ps1','keep the original HTTP filename');
assert.equal(savedHttpObjects.filter(x=>x.kind.startsWith('HTTP response object'))[1].name,'checking (2).ps1','avoid overwriting repeated object names');
assert.equal(savedHttpObjects.filter(x=>x.kind.startsWith('HTTP response object'))[0].packets[0],4221);

assert.equal(savedHttpObjects.filter(x=>x.kind.startsWith('HTTP response object'))[0].duplicateCount, 1);

// Identical reconstructed bytes collapse to one item while preserving provenance.
const duplicateRows=[];
const addDuplicateTest=new Function('recoveries','signature','scanRecoveredFile',recoveryCode+'; return addRecovery')(
  duplicateRows, bytes => ({label:'Test binary',ext:'bin'}), scanRecoveredFile
);
const identicalA=Uint8Array.from({length:256},(_,i)=>(i*17)%256);
const identicalB=identicalA.slice();
addDuplicateTest(duplicateRows,'first.bin','HTTP response object · application/octet-stream',identicalA,[10,11],'first observation');
addDuplicateTest(duplicateRows,'renamed.bin','TCP file carving',identicalB,[12,11],'second observation');
assert.equal(duplicateRows.length,1,'identical bytes are represented once');
assert.equal(duplicateRows[0].duplicateCount,2,'duplicate occurrence count is retained');
assert.deepEqual(duplicateRows[0].packets,[10,11,12],'packet provenance is merged and unique');
assert.deepEqual(duplicateRows[0].sourceNames,['first.bin','renamed.bin'],'alternate names are retained');
assert.equal(duplicateRows[0].priority,95,'strongest source priority is retained');

// A same-length sampled-fingerprint collision must not collapse different bytes.
const collisionRows=[];
const addCollisionTest=new Function('recoveries','signature','scanRecoveredFile',recoveryCode+'; return addRecovery')(
  collisionRows, bytes => ({label:'Test binary',ext:'bin'}), scanRecoveredFile
);
const collisionA=new Uint8Array(1024), collisionB=new Uint8Array(1024);
collisionB[1]=1; // index 1 is outside the 4-byte-stride sample
addCollisionTest(collisionRows,'a.bin','TCP file carving',collisionA,[1],'candidate A');
addCollisionTest(collisionRows,'b.bin','TCP file carving',collisionB,[2],'candidate B');
assert.equal(collisionRows.length,2,'full byte comparison guards sampled-fingerprint collisions');
assert.ok(html.includes('ครั้ง xuất hiện') || html.includes('lần xuất hiện'), 'recovery UI exposes duplicate occurrence counts');
assert.ok(html.includes('sourceNames'), 'recovery metadata retains alternate source names');

const assessIntegrity=new Function('byteText',recoveryCode+'; return assessRecoveryIntegrity')(byteText);
const pngEnd=Uint8Array.of(0,0,0,0,73,69,78,68,174,66,96,130);
assert.equal(assessIntegrity(pngEnd,'png','complete candidate').status,'marker','PNG end marker is recognized without claiming full validation');
assert.equal(assessIntegrity(pngEnd,'png','sequence gap giữa các chunk; candidate có thể thiếu dữ liệu.').status,'possible','known sequence gaps take precedence over a format marker');
assert.equal(assessIntegrity(Uint8Array.of(255,216,1),'jpg','candidate').status,'possible','missing JPEG EOI is flagged as possibly truncated');
assert.equal(assessIntegrity(Uint8Array.of(1,2,3),'bin','candidate').status,'unverified','unknown formats stay explicitly unverified');
const pdfEnd=byteText('body\n%%EOF\n');
assert.equal(assessIntegrity(pdfEnd,'pdf','candidate').status,'marker');
const zipEnd=Uint8Array.of(80,75,5,6,...new Uint8Array(18));
assert.equal(assessIntegrity(zipEnd,'zip','candidate').status,'marker');
console.log('PASS recovered-file integrity markers and conservative completeness labels');
console.log('PASS exact-content recovery deduplication, packet provenance, and collision guard');


const riskyScript=scanRecoveredFile('check.ps1','HTTP response object',byteText('$c.DownloadString($u); Invoke-Expression $c'),{ext:'txt',label:'Text'});
assert.equal(riskyScript.level,'high');
assert.ok(riskyScript.signals.length>=3);
assert.equal(riskyScript.engine,'heuristic-static');
const executableBytes=new Uint8Array(128);executableBytes[0]=0x4d;executableBytes[1]=0x5a;executableBytes[0x3c]=64;executableBytes[64]=0x50;executableBytes[65]=0x45;
const peAlert=scanRecoveredFile('payload.exe','HTTP response object',executableBytes,{ext:'exe',label:'Windows PE / MZ'});
assert.equal(peAlert.level,'medium','executable format is a warning, not a confirmed virus verdict');
assert.equal(scanRecoveredFile('readme.txt','HTTP response object',byteText('just ordinary notes'),{ext:'txt',label:'Text'}),null);
const disguised=scanRecoveredFile('invoice.txt','HTTP response object',executableBytes,{ext:'exe',label:'Windows PE / MZ'});
assert.ok(disguised.signals.some(x=>x.includes('không khớp')));
assert.ok(html.includes('heuristic, không xác nhận virus'), 'UI distinguishes heuristic warnings from antivirus verdicts');
assert.ok(html.includes('Không mở/chạy trực tiếp'), 'UI tells users to avoid executing recovered files');
console.log('PASS recovered-file malware heuristics and safe handling');


assert.equal(httpTools.httpPathFilename('/downloads/checking.ps1?token=1'),'checking.ps1','infer response filenames from matching request URI');
const multipartBody=byteText('--boundary42\r\nContent-Disposition: form-data; name="upload"; filename="ichigo-lite.ps1"\r\nContent-Type: application/octet-stream\r\n\r\nWrite-Output "lab"\r\n--boundary42--\r\n');
const multipartFiles=httpTools.extractMultipartFiles(multipartBody,'multipart/form-data; boundary=boundary42');
assert.equal(multipartFiles.length,1);
assert.equal(multipartFiles[0].name,'ichigo-lite.ps1');
assert.equal(new TextDecoder().decode(multipartFiles[0].bytes),'Write-Output "lab"');
assert.ok(html.includes('extractMultipartFiles(obj.body,obj.contentTypeHeader)'), 'HTTP upload bodies are split into individual multipart file candidates');


const signatureCode = sliceBetween('function signature(b){', 'function scanRecoveredFile(name,kind,bytes,sig){');
const signature = new Function(signatureCode + '; return signature')();
const sampleSignatures=[
  [Uint8Array.of(0x53,0x51,0x4c,0x69,0x74,0x65,0x20,0x66,0x6f,0x72,0x6d,0x61,0x74,0x20,0x33,0),'sqlite'],
  [Uint8Array.of(0x1f,0x8b,8,0),'gz'],
  [Uint8Array.of(0xfd,0x37,0x7a,0x58,0x5a,0),'xz'],
  [Uint8Array.of(0x28,0xb5,0x2f,0xfd),'zst'],
  [Uint8Array.of(0x04,0x22,0x4d,0x18),'lz4'],
  [byteText('RIFF\x00\x00\x00\x00WAVE'),'wav'],
  [byteText('RIFF\x00\x00\x00\x00AVI '),'avi'],
  [byteText('....ftypisom'),'mp4'],
  [Uint8Array.of(0x1a,0x45,0xdf,0xa3,0x01,0x02,0x03,0x04),'webm'],
  [Uint8Array.of(0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1),'ole'],
  [Uint8Array.of(0x4d,0x53,0x43,0x46,0,0,0,0),'cab'],
  [byteText('SQLite format 3\0'),'sqlite'],
  [byteText('{"valid":true}'),'json'],
  [byteText('<?xml version="1.0"?>'),'xml'],
  [byteText('<!doctype html><html>'),'html'],
  [byteText('{\\rtf1 sample}'),'rtf'],
];
for(const [bytes,ext] of sampleSignatures)assert.equal(signature(bytes).ext,ext,'recognize '+ext);
const pcapng=Uint8Array.from([0x0a,0x0d,0x0d,0x0a,...Array(20).fill(0)]);
assert.equal(signature(pcapng).ext,'pcapng');
const carveCode=sliceBetween('const RECOVERY_MAGIC_PATTERNS=', 'function decodeB32(s){');
const formatRead16=(d,o,l)=>l?d[o]|d[o+1]<<8:d[o]<<8|d[o+1];
const formatRead32=(d,o,l)=>l?(d[o]|d[o+1]<<8|d[o+2]<<16|d[o+3]<<24)>>>0:(d[o]*0x1000000+d[o+1]*65536+d[o+2]*256+d[o+3])>>>0;
const carveApi=new Function('signature','u16','u32',carveCode+'; return {findMagicCandidates,carvedObjectEnd}')(signature,formatRead16,formatRead32);
const carveStream=joinBytes([Uint8Array.of(0,1,2),Uint8Array.from([0x89,0x50,0x4e,0x47,13,10,26,10,0,0,0,0,0,0,0,0,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82]),byteText('%PDF-1.7\\nbody\\n%%EOF')]);
const found=carveApi.findMagicCandidates(carveStream);
assert.deepEqual(found.map(x=>x.ext),['png','pdf'],'carve multiple known formats from a single stream');
assert.equal(carveApi.carvedObjectEnd(carveStream,found[0].offset,found[1].offset),found[1].offset,'stop at the PNG terminator before the next object');
console.log('PASS expanded signatures and multi-object stream carving');

// IPv4 fragment assembly using reversed arrival order and incomplete datagram.
const ipCode = sliceBetween('function reassembleIpv4Fragments(list){', 'function ascii(d){');
const magicRead16 = (d, o, little) => little ? d[o] | d[o + 1] << 8 : d[o] << 8 | d[o + 1];
const ipv4 = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
const parseFrame = (raw, linkType, no) => ({
  no, proto: 'UDP', raw, linkType, payload: raw.slice(34),
  src: '10.0.0.1', dst: '10.0.0.2'
});
const reassembleIp = new Function('u16', 'ip4', 'parseFrame', ipCode + '; return reassembleIpv4Fragments')(
  magicRead16, ipv4, parseFrame
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
const magicRead32 = (d, o, little) => little ? (d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24) >>> 0 : (d[o] * 0x1000000 + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3]) >>> 0;
const ip6 = (d, o) => [...Array(8)].map((_, i) => ((d[o + 2*i] << 8) | d[o + 2*i + 1]).toString(16)).join(':');
const reassembleIp6 = new Function('u16', 'u32', 'ip6', 'parseFrame', ipv6Code + '; return reassembleIpv6Fragments')(
  magicRead16, magicRead32, ip6, parseFrame
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
  for(let j=0;j<24;j++){seed=(seed*1664525+1013904223)>>>0;label+='abcdefghijklmnopqrstuvwxyz234567'[seed>>>27]}
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



const timelineCode = sliceBetween('function buildTimelineEvents(){', 'function timelineHtml(){');
const buildTimeline = (packets, findings, domains, recoveries, sensitiveData) =>
  new Function('packets','findings','domains','recoveries','sensitiveData',
    timelineCode + '; return buildTimelineEvents'
  )(packets, findings, domains, recoveries, sensitiveData)();
const timeline = buildTimeline(
  [{no:1,time:10},{no:2,time:20}],
  [{severity:'high',title:'Suspicious pattern',desc:'Check it',ref:'Packets 2, 1'}],
  [{name:'example.org',first:1,count:3,queries:3,responses:2}],
  [{name:'recovered.bin',kind:'HTTP',size:4,packets:[1]}],
  [{type:'Password',value:'must-not-appear',packets:[2],confidence:'Cao'}]
);
assert(timeline.length >= 5);
assert(timeline.every((event,i) => i===0 || timeline[i-1].time <= event.time));
assert(!timeline.some(event => event.detail.includes('must-not-appear')));

const planCode = sliceBetween('function investigationPlan(){', 'function investigationWorkflowHtml(){');
const buildPlan = (goal, findings, recoveries, sensitiveData, packets, conversations) =>
  new Function('investigationGoal','findings','recoveries','sensitiveData','packets','conversations',
    planCode + '; return investigationPlan'
  )(goal, findings, recoveries, sensitiveData, packets, conversations)();
const autoCredentials = buildPlan('auto',[{severity:'high',title:'test',desc:'evidence',ref:'packet 1'}],[{}],[{}],[],[]);
assert.equal(autoCredentials.goal,'credentials');
assert.equal(autoCredentials.view,'sensitive');
const autoRecovery = buildPlan('auto',[],[{}],[],[],[]);
assert.equal(autoRecovery.goal,'recovery');
const autoCovert = buildPlan('auto',[{severity:'medium',title:'Mẫu DNS có thể mang dữ liệu dạng tunnel',desc:'x',ref:'p'}],[],[],[],[]);
assert.equal(autoCovert.goal,'covert');
const explicitAttack = buildPlan('attack',[],[],[],[],[]);
assert.equal(explicitAttack.goal,'attack');
assert.equal(explicitAttack.view,'findings');
const tlsPlan = buildPlan('questions',[],[],[],[{app:'TLS'}],[]);
assert.equal(tlsPlan.tlsPackets,1);

console.log('PASS: timeline ordering/redaction, guided workflow, end-to-end detection rules, SYN tuple matching, TCP secret reassembly, SHA-256, sliding windows, DNS entropy and ARP timing, syntax, TCP reorder/retransmit/gap/conflict, multiple HTTP responses, IPv4 and IPv6 complete/incomplete fragments');


// Case notes are isolated per capture hash and safely stored as local JSON.
const notesCode = sliceBetween('function getNotesStorage(){', 'function investigationPlan(){');
const notes = new Function(notesCode + '; return {caseNotesStorageKey,readStoredCaseNotes,writeStoredCaseNotes}')();
const notesKeyA = notes.caseNotesStorageKey('sha256-a', 'one.pcap');
const notesKeyB = notes.caseNotesStorageKey('sha256-b', 'one.pcap');
assert.notEqual(notesKeyA, notesKeyB, 'notes for different capture hashes are isolated');
assert.equal(notes.caseNotesStorageKey('', 'one.pcap'), notes.caseNotesStorageKey('', 'one.pcap'));
assert.notEqual(notes.caseNotesStorageKey('', 'one.pcap'), notes.caseNotesStorageKey('', 'two.pcap'));
const memoryStorage = new Map();
const storage = {
  getItem: key => memoryStorage.get(key) ?? null,
  setItem: (key, value) => memoryStorage.set(key, value),
};
assert.equal(notes.writeStoredCaseNotes(storage, notesKeyA, 'Investigate suspicious DNS', '2026-11-22T10:00:00.000Z'), true);
assert.deepEqual(notes.readStoredCaseNotes(storage, notesKeyA), {text:'Investigate suspicious DNS', updatedAt:'2026-11-22T10:00:00.000Z'});
assert.deepEqual(notes.readStoredCaseNotes(storage, notesKeyB), {text:'', updatedAt:''});
assert.deepEqual(notes.readStoredCaseNotes({getItem(){return '{bad json'}}, notesKeyA), {text:'', updatedAt:''});
assert.equal(notes.writeStoredCaseNotes({setItem(){throw Error('quota')}}, notesKeyA, 'x', 'now'), false);
console.log('PASS case notes storage, isolation, and failure handling');


// Correlate repeated alert evidence by shared IPv4, without treating correlation as proof.
const correlationCode = sliceBetween('function correlateFindings(){', 'function incidentCorrelationsHtml(){');
const correlate = new Function('findings', correlationCode + '; return correlateFindings')( [
  {severity:'medium', title:'DNS tunnel candidate', ref:'DNS example.test · packets 2, 3', desc:'client 10.1.2.3 queried 198.51.100.20'},
  {severity:'high', title:'Possible beacon', ref:'Packets 9, 11', desc:'Outbound 10.1.2.3 → 203.0.113.9'},
  {severity:'low', title:'Unrelated event', ref:'Packet 18', desc:'Host 10.2.3.4 contacted 192.0.2.8'},
  {severity:'high', title:'Bogus address event', ref:'Packet 22', desc:'255.999.1.1 and 127.0.0.1'},
])();
assert.equal(correlate.length, 1, 'only IPs shared by multiple alerts are grouped');
assert.equal(correlate[0].ip, '10.1.2.3');
assert.equal(correlate[0].items.length, 2);
assert.equal(correlate[0].severity, 'high', 'cluster priority follows its strongest alert');
assert.ok(html.includes('mối liên hệ thống kê, không tự chứng minh'), 'UI states correlation limits');
assert.ok(html.includes("$('#v-findings').onclick"), 'correlation control is delegated from its containing view');
assert.ok(html.includes("value='ip:'"), 'correlation action pivots packet search');
console.log('PASS shared-IP correlation, priority, filtering, and caveat');
