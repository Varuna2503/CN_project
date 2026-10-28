# NetCfg-AI — Validator-Guided, RAG-Grounded Cisco IOS Configuration Generator

Natural language ("I need VLAN + DHCP + OSPF") -> validated, explained, deployment-ready Cisco IOS config.
Existing configs can be audited too: paste a `show running-config`, get a scored report and a repaired version.

## Pipeline
1. Intent extraction: LLM (any OpenAI-compatible endpoint: Llama 3 / Qwen / Mistral / GPT) or offline rule parser
   (VLAN ids and names, host counts, hostname, base network, DNS, OSPF area, NTP/syslog servers)
2. Addressing plan: VLAN id -> third octet (192.168.10.0/24 for VLAN 10), or VLSM (largest subnet first) when
   host counts are given ("sales 120 hosts" -> /25); DHCP exclusions shrink to fit small subnets
3. RAG retrieval over Cisco docs / RFC / best-practice corpus (TF-IDF here; swap for embeddings + vector DB)
4. Generation with per-line provenance (each command tagged with the knowledge source that justified it)
5. Deterministic validation, every finding tied to a line, a category and a fix hint:
   - syntax: grammar by CLI mode (strict for generated configs, lenient for audits: unknown commands are INFO)
   - addressing: VLAN range, subnet overlap, network/broadcast used as host, SVI without VLAN, shut interfaces
   - routing: inter-VLAN routing, OSPF coverage, passive LAN interfaces, router-id, IPv6 prerequisites
   - services: DHCP <-> gateway, DHCP DNS, ACL/NAT/QoS reference integrity
   - security: SSH-only VTYs, `no login`, `login local` without users, enable/user secrets, brute-force blocking,
     SNMP default communities, disabled exec-timeout, HTTP server
6. Closed-loop repair (multi-pass): missing globals, Telnet, wrong DHCP gateway, OSPF coverage holes, passive
   interfaces, router-id, VTY login/transport, plaintext user passwords, `enable password`
7. Per-command explanations, topology, verification plan and a machine-readable report

## Web UI (live demo)
    python app.py            # then open http://localhost:8000   (python app.py 8080 for another port)
- **Generate** mode: type a requirement; *Options* override device type, hostname, base network and DNS.
  Tick *Inject faulty draft* to watch the validator catch and repair a bad draft (missing globals, Telnet,
  wrong DHCP gateway, OSPF hole).
- **Audit config** mode: paste or drop a config file (or load the insecure sample) and get it scored and repaired.
- Each result has a score ring, the draft -> repaired score history, and per-category checks, plus these tabs:
  - Configuration: line numbers, knowledge-source gutter, hover/click inspector, and a *Changes* diff against
    the draft
  - Topology (drawn from the final config), Explained (filterable), Validation (click a finding to jump to
    its line), Verify (Packet Tracer checklist), Intent & sources (addressing plan, RAG relevance, timings)
- Export: copy, or download config / explained.md / verify.md / report.json. *Console-paste wrapper* adds
  `enable / configure terminal ... end / write memory`; the *secret* box replaces the `CHANGE_ME_Str0ng`
  placeholder in exports only (never sent to the server).
- History of the last 15 results is kept in the browser; light/dark theme toggle.
No pip installs needed (standard library only).

API: `POST /api/generate {"request", "inject_fault", "options": {device, hostname, base, dns}}`,
`POST /api/audit {"config", "repair"}`, `GET /api/health`.

## Run (command line)
    python netcfg_ai.py "3 VLANs (sales, hr, guest) with DHCP, OSPF, NAT, QoS, IPv6; block guest"
    python netcfg_ai.py "3 VLANs (sales 120 hosts, hr 40 hosts, guest 25 hosts) with DHCP and OSPF"   # VLSM
    python netcfg_ai.py "branch router, sales and hr, NTP and syslog" --hostname BR-R2 --base 10.20.0.0/16
    python netcfg_ai.py "layer 3 switch with VLAN 10, 20, DHCP, OSPF" --inject-fault   # shows repair loop
    python netcfg_ai.py --validate-only some_config.txt [--repair]                     # audit any config
Outputs: output/config.txt (paste into Packet Tracer / GNS3 / CML), explained.md, verify.md, report.json

## Test in a simulator
Paste config.txt into a router in Packet Tracer/GNS3/EVE-NG and work through verify.md (or the Verify tab):
`show ip interface brief`, `show ip ospf neighbor`, `show ip dhcp binding`, `show access-lists`,
`show ip nat translations`, plus client pings, including the ones that should fail because of the guest ACL.
Replace CHANGE_ME_Str0ng and the 192.0.2.x documentation addresses (NTP/syslog placeholders) before real use.

## Evaluation plan (for report / paper)
- Benchmark: 50-100 NL requirements of increasing complexity
- Metrics: syntax-validity rate, semantic-validity rate, simulator pass rate (GNS3/CML), compliance score,
  first-pass vs post-repair success, latency, human-edit distance
- Baselines: (a) raw LLM, (b) LLM + RAG, (c) template tool, (d) full system (ablation shows validator loop gain)
- The audit mode doubles as an evaluation harness: run raw LLM outputs through `--validate-only` to score them
