# Saitama PCAP Workbench

Browser based PCAP and PCAPNG triage for the Saitama network forensics exercise.

## Use

Open `index.html` in a modern browser and choose a `.pcap` or `.pcapng` file. The capture is parsed locally in the browser by default. The optional AI panel uploads the entire capture only after the user configures a Worker, checks the consent box, and clicks the AI button. The Worker forwards the raw capture to OpenAI Files and Code Interpreter; PCAP payloads may contain credentials or private data. The app's metadata summary omits credential values and case notes, but the raw file is not redacted. AI upload is limited to 25 MiB. Use the tabs to review packets, TCP/UDP conversations, DNS queries, heuristic findings, and the generated report. Export packet CSV or the complete analysis JSON from the overview.

## Deployment

This static page is published at:

`https://thienngo2910.github.io/saitama-pcap-workbench/`

The source lives in the `saitama-pcap-workbench/` directory of the existing `thienngo2910.github.io` GitHub Pages repository. The rest of that site is left untouched.

## Optional OpenAI analysis

The browser app is static, so it never contains an OpenAI API key. Deploy the Worker in `worker/` and set secrets in Cloudflare:

```powershell
cd worker
npx wrangler login
npx wrangler secret put OPENAI_API_KEY
npx wrangler secret put AI_GATE_TOKEN
npx wrangler deploy
```

Generate a random gate token locally (do not commit it):

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Enter the deployed Worker URL and the same gate token in the AI panel. The token is kept in page memory and is cleared when the analysis is cleared or the page is reloaded. The Worker accepts requests only from the published GitHub Pages origin, validates PCAP/PCAPNG magic, and rejects files larger than 25 MiB. It uploads the original capture to OpenAI so Code Interpreter can inspect it in a Python sandbox. It asks the model to follow the Network Forensics flow, cite packet/frame evidence, treat capture text as untrusted data, and redact credential values in its response. The Worker requests deletion of the temporary OpenAI file and container after analysis; cleanup is best effort, and OpenAI retention/monitoring policies still apply. OpenAI API and Code Interpreter usage may incur charges. Review your provider settings and capture contents before enabling upload.

Worker tests run with `node --test tests/ai-worker.test.mjs`.

## Current analysis coverage

- Classic PCAP in little/big endian and microsecond/nanosecond timestamp formats.
- PCAPNG section, interface and enhanced packet blocks; Ethernet, Linux cooked v1/v2, raw IPv4.
- Ethernet VLAN tags, IPv4/IPv6, ARP, TCP, UDP, ICMP/ICMPv6 packet summaries.
- DNS question names/types, endpoint and protocol counts, bidirectional TCP/UDP conversation grouping.
- Heuristic flags for cleartext services and visible credential-like strings, plus unusually long DNS names.
- Packet table filtering, CSV packet export, JSON findings export, and a text report.

Heuristic results are triage indicators, not proof of malicious activity. Validate findings against the original capture and the network context. The current parser does not reassemble TCP streams or decode TLS-encrypted application data.

