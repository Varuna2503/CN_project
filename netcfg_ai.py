#!/usr/bin/env python3
"""
NetCfg-AI: validator-guided, RAG-grounded natural-language -> Cisco IOS configuration generator.

Pipeline:
  NL requirement -> intent (LLM or offline rules) -> addressing plan (VLAN-id octets or VLSM by host count)
  -> RAG retrieval -> config generation with per-line provenance -> deterministic validation (syntax +
  semantic + security compliance) -> automatic repair loop -> per-command explanations, topology and a
  verification plan. Any existing config can also be audited (validated + repaired) without generating.

Usage:
  python netcfg_ai.py "3 VLANs (sales 120 hosts, hr 40 hosts, guest 25 hosts) with DHCP, OSPF, NAT; block guest"
  python netcfg_ai.py "VLAN + DHCP + OSPF" --inject-fault
  python netcfg_ai.py "branch router with sales and hr, NTP and syslog" --hostname BR-R2 --base 10.20.0.0/16
  python netcfg_ai.py --validate-only my_running_config.txt [--repair]

Optional LLM backend (any OpenAI-compatible endpoint, e.g. Ollama running Llama 3 / Qwen / Mistral):
  export LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=llama3  [LLM_API_KEY=...]
Without it, a deterministic rule-based intent parser is used so the project runs fully offline.
"""
import argparse, difflib, ipaddress, json, math, os, re, time, urllib.request
from collections import Counter

IP = r"(?:\d{1,3}\.){3}\d{1,3}"

# ----------------------------------------------------------------------------------------
# 1. Knowledge base for retrieval (prototype corpus; replace/extend with Cisco docs, CVDs, RFCs)
# ----------------------------------------------------------------------------------------
KB = {
    "KB-BASE": ("Device hardening baseline (CIS / Cisco hardening guide)",
                "hostname ssh version 2 service password-encryption enable secret disable http server telnet "
                "transport input ssh vty login local rsa key domain-name security best practice hardening banner "
                "login block-for brute force attempts password min-length exec-timeout console"),
    "KB-ADDR": ("IPv4 addressing and VLSM (RFC 950, RFC 1878, RFC 1918)",
                "subnet subnetting vlsm hosts users devices clients prefix mask wildcard addressing plan size "
                "capacity private block range base network"),
    "KB-VLAN": ("VLANs, SVIs, router-on-a-stick (IEEE 802.1Q)",
                "vlan id name range 1 to 4094 reserved 1002 1005 interface vlan svi inter-vlan routing ip routing "
                "layer 3 switch subinterface encapsulation dot1q router on a stick trunk gateway"),
    "KB-DHCP": ("DHCP server on IOS (RFC 2131)",
                "dhcp pool network default-router dns-server lease excluded-address gateway scope addresses dns"),
    "KB-OSPF": ("OSPFv2/v3 (RFC 2328, RFC 5340)",
                "ospf router-id network wildcard area 0 passive-interface default-information originate routing "
                "dynamic protocol backbone neighbor adjacency ospfv3 ipv6 router ospf"),
    "KB-ACL": ("Access control lists (RFC 1918 private ranges, Cisco ACL guide)",
               "access-list extended standard named permit deny access-group in out guest block restrict firewall "
               "policy isolation implicit deny"),
    "KB-NAT": ("NAT/PAT overload (RFC 3022, RFC 1918)",
               "nat inside outside source list overload pat internet public default route translation"),
    "KB-QOS": ("QoS: MQC and DSCP (RFC 2474, RFC 4594)",
               "qos class-map policy-map dscp ef af41 priority bandwidth percent voice video service-policy "
               "output congestion latency"),
    "KB-IPV6": ("IPv6 on IOS (RFC 8200, RFC 3849 documentation prefix)",
                "ipv6 unicast-routing ipv6 address 2001:db8 prefix /64 dual stack ospfv3"),
    "KB-MGMT": ("Management plane: NTP and syslog (RFC 5905, RFC 5424)",
                "ntp server time clock sync synchronisation timestamps logging syslog log host trap severity "
                "monitoring audit trail"),
}


def tok(t):
    return re.findall(r"[a-z0-9]+", t.lower())


class Retriever:
    """Minimal TF-IDF retriever (swap for FAISS/Chroma + embeddings in the full system)."""

    def __init__(self, kb):
        self.ids = list(kb)
        self.docs = [Counter(tok(kb[i][0] + " " + kb[i][1])) for i in self.ids]
        n = len(self.docs)
        df = Counter(w for d in self.docs for w in d)
        self.idf = {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()}

    def _vec(self, c):
        return {w: f * self.idf.get(w, 0) for w, f in c.items()}

    def search(self, q, k=4):
        qv = self._vec(Counter(tok(q)))
        qn = math.sqrt(sum(v * v for v in qv.values())) or 1
        out = []
        for i, d in zip(self.ids, self.docs):
            dv = self._vec(d)
            dn = math.sqrt(sum(v * v for v in dv.values())) or 1
            s = sum(qv[w] * dv.get(w, 0) for w in qv) / (qn * dn)
            out.append((s, i))
        return [(round(s, 3), i) for s, i in sorted(out, reverse=True)[:k] if s > 0]


RETRIEVER = Retriever(KB)

# ----------------------------------------------------------------------------------------
# 2. Intent extraction (LLM if configured, deterministic rules otherwise)
# ----------------------------------------------------------------------------------------
NAMES = ["sales", "hr", "it", "finance", "guest", "management", "engineering", "servers", "voice", "staff",
         "students", "admin", "marketing", "faculty", "library", "accounts", "research", "printers", "cctv",
         "iot", "dev", "ops"]
HOSTS = r"(\d{1,5})\s*(?:hosts?|users?|devices?|clients?|pcs?|computers?|endpoints?)\b"
DEFAULT_HOST = {"router": "EDGE-R1", "l3switch": "CORE-SW1"}
WAN_CANDIDATES = ["10.0.0.0/30", "172.31.255.252/30", "192.168.255.252/30", "100.64.0.0/30"]
NTP_PLACEHOLDER, SYSLOG_PLACEHOLDER = "192.0.2.123", "192.0.2.50"

SCHEMA_HINT = """Return ONLY JSON: {"device":"router|l3switch","hostname":str,
"vlans":[{"id":int,"name":str,"hosts":int|null}],"dhcp":bool,"ospf":bool,"acl":bool,"nat":bool,"qos":bool,
"ipv6":bool,"ntp":bool,"syslog":bool,"dns":[str],"base":"CIDR or null","ospf_area":int}"""


def rule_intent(text):
    t = text.lower()
    it = dict(hostname=DEFAULT_HOST["router"], device="router", vlans=[], dhcp=False, ospf=False, acl=False,
              nat=False, qos=False, ipv6=False, ntp=False, syslog=False, ntp_server=None, syslog_server=None,
              dns=[], base=None, ospf_area=0, notes=[])
    if re.search(r"layer\s*-?3 switch|l3 switch|\bswitch\b|\bsvi\b", t) and "router" not in t:
        it["device"] = "l3switch"
        it["hostname"] = DEFAULT_HOST["l3switch"]
    h = re.search(r"\bhostname\s+([a-z][\w-]*)|\b(?:router|switch|device)\s+(?:named|called)\s+([a-z][\w-]*)",
                  text, re.I)
    if h:
        it["hostname"] = h.group(1) or h.group(2)
    it["dhcp"] = "dhcp" in t
    it["ospf"] = "ospf" in t
    it["nat"] = bool(re.search(r"\bnat\b|\bpat\b|internet access", t))
    it["qos"] = bool(re.search(r"\bqos\b|quality of service|voice|prioriti", t))
    it["ipv6"] = "ipv6" in t
    it["acl"] = bool(re.search(r"\bacl\b|block|deny|restrict|firewall|isolate", t))
    it["ntp"] = bool(re.search(r"\bntp\b|time sync|clock sync", t))
    it["syslog"] = bool(re.search(r"syslog|\blogging\b|log server", t))
    if m := re.search(rf"\bntp(?:\s+server)?\s*(?:at|is|=|:)?\s*({IP})", t):
        it["ntp_server"] = m.group(1)
    if m := re.search(rf"(?:syslog|logging|log server)(?:\s+(?:server|host))?\s*(?:at|is|to|=|:)?\s*({IP})", t):
        it["syslog_server"] = m.group(1)
    if m := re.search(rf"\bdns(?:[\s-]*servers?)?\s*(?:at|is|of|=|:)?\s*({IP}(?:\s*(?:,|and|&|/)\s*{IP})*)", t):
        it["dns"] = re.findall(IP, m.group(1))
    if m := re.search(r"\barea\s*(\d{1,5})\b", t):
        it["ospf_area"] = int(m.group(1))
    if m := re.search(rf"\b({IP}/\d{{1,2}})", t):
        it["base"] = m.group(1)

    # host counts: "50 users each", "sales (120 hosts)", "40 hosts for hr", "vlan 10 with 30 devices"
    each = re.search(HOSTS + r"\s*(?:each|per\s+vlan|apiece)|\beach\s+(?:with\s+|having\s+)?" + HOSTS, t)
    default_hosts = int(each.group(1) or each.group(2)) if each else None
    t2 = t[:each.start()] + " " + t[each.end():] if each else t
    it_ok = bool(re.search(r"\bIT\b", text) or re.search(r"\bit\s+(?:vlan|dept|department|team|staff)\b", t))
    nm = "|".join(NAMES)
    by_name, by_id = {}, {}
    for m in re.finditer(r"\b(" + nm + r")\b[^,;.\d]{0,14}?" + HOSTS, t2):
        by_name.setdefault(m.group(1), int(m.group(2)))
    for m in re.finditer(HOSTS + r"\s+(?:for|in|on)\s+(?:the\s+)?(" + nm + r")\b", t2):
        by_name.setdefault(m.group(2), int(m.group(1)))
    for m in re.finditer(r"vlan\s*(\d{1,4})[^,;.\d]{0,14}?" + HOSTS, t2):
        by_id.setdefault(int(m.group(1)), int(m.group(2)))

    ids = []
    for m in re.finditer(r"vlans?\s*(\d{1,4}(?:\s*(?:,|and|&)\s*\d{1,4})*)", t):
        ids += [int(x) for x in re.findall(r"\d+", m.group(1)) if int(x) not in ids]
    names = []
    for m in re.finditer(r"(?<!dns )(?<!ntp )(?<!log )\b(" + nm + r")\b", t):
        if m.group(1) not in names and (m.group(1) != "it" or it_ok):
            names.append(m.group(1))
    cnt = re.search(r"(\d+)\s*vlans?", t)
    if not ids and ("vlan" in t or by_name or (default_hosts and names)):
        n = int(cnt.group(1)) if cnt else (len(names) if by_name or default_hosts else max(len(names), 3))
        n = min(max(n, len(names)), 64)
        ids = [10 * (i + 1) for i in range(n)]
    for i, vid in enumerate(ids):
        name = names[i] if i < len(names) else f"VLAN{vid}"
        it["vlans"].append({"id": vid, "name": name.upper(),
                            "hosts": by_name.get(name) or by_id.get(vid) or default_hosts})
    return it


def llm_intent(text, context, base):
    url = os.environ["LLM_BASE_URL"].rstrip("/") + "/chat/completions"
    body = {"model": os.environ.get("LLM_MODEL", "llama3"), "temperature": 0,
            "messages": [{"role": "system", "content": "You extract network intent.\n" + SCHEMA_HINT +
                          "\nGrounding context:\n" + context},
                         {"role": "user", "content": text}]}
    req = urllib.request.Request(url, json.dumps(body).encode(), {
        "Content-Type": "application/json", "Authorization": "Bearer " + os.environ.get("LLM_API_KEY", "none")})
    raw = json.load(urllib.request.urlopen(req, timeout=60))["choices"][0]["message"]["content"]
    data = json.loads(re.search(r"\{.*\}", raw, re.S).group(0))
    base.update({k: v for k, v in data.items() if k in base and v is not None})
    return base


def apply_options(it, op):
    """Explicit overrides from the UI / CLI flags win over whatever the parser extracted."""
    dev = op.get("device")
    if dev in DEFAULT_HOST and dev != it["device"]:
        if it["hostname"] == DEFAULT_HOST.get(it["device"]):
            it["hostname"] = DEFAULT_HOST[dev]
        it["device"] = dev
        it["notes"].append(f"Device forced to {dev} by option.")
    if op.get("hostname"):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", op["hostname"]):
            raise ValueError("Hostname must start with a letter and contain only letters, digits and '-'.")
        it["hostname"] = op["hostname"]
    if op.get("base"):
        try:
            net = ipaddress.ip_network(op["base"], strict=False)
        except ValueError:
            raise ValueError(f"'{op['base']}' is not a valid base network (use CIDR, e.g. 10.20.0.0/16).")
        it["base"] = str(net)
    if op.get("dns"):
        dns = re.findall(IP, op["dns"])
        if not dns or not all(valid_ip(d) for d in dns):
            raise ValueError(f"'{op['dns']}' is not a list of IPv4 DNS servers.")
        it["dns"] = dns
    return it


def reserve_for(usable):
    """Addresses kept out of DHCP at the start of a subnet (gateway + room for static hosts)."""
    return max(1, min(10, usable // 8))


def prefix_for(hosts):
    """Smallest prefix whose usable addresses hold the hosts plus the gateway."""
    for p in range(30, 7, -1):
        if 2 ** (32 - p) - 2 >= hosts + 1:
            return p
    raise ValueError(f"{hosts} hosts do not fit in a single IPv4 subnet.")


def plan_addresses(it):
    """VLAN id -> third octet when it fits (192.168.<id>.0/24); otherwise VLSM, largest subnet first."""
    try:
        base = ipaddress.ip_network(it.get("base") or "192.168.0.0/16", strict=False)
    except ValueError:
        raise ValueError(f"'{it['base']}' is not a valid base network.")
    if base.version != 4 or base.prefixlen > 30:
        raise ValueError(f"Base network {base} must be an IPv4 block of /30 or larger.")
    vl = it["vlans"]
    size = lambda v: prefix_for(v["hosts"]) if v["hosts"] else 24
    nets = None
    if not any(v["hosts"] for v in vl) and base.prefixlen <= 16:
        cand = [ipaddress.ip_network((int(base.network_address) + (v["id"] % 256) * 256, 24)) for v in vl]
        if len(set(cand)) == len(cand):
            nets = {v["id"]: n for v, n in zip(vl, cand)}
    it["vlsm"] = nets is None
    if nets is None:
        nets, cur = {}, int(base.network_address)
        for v in sorted(vl, key=size):
            net = ipaddress.ip_network((cur, size(v)))
            if not net.subnet_of(base):
                raise ValueError(f"{base} is too small for the requested VLANs; use a larger base network.")
            nets[v["id"]] = net
            cur += net.num_addresses
    for v in vl:
        net = nets[v["id"]]
        usable = net.num_addresses - 2
        r = max(1, min(reserve_for(usable), usable - v["hosts"])) if v["hosts"] else reserve_for(usable)
        v.update(net=str(net), gw=str(net.network_address + 1), mask=str(net.netmask), wildcard=str(net.hostmask),
                 reserved=r, capacity=usable - r, pool=f"{net.network_address + r + 1} - {net.broadcast_address - 1}")
    it["base"] = str(base)
    if vl:
        it["notes"].append(f"Addressing: VLSM inside {base}, largest subnet first, sized by host count."
                           if it["vlsm"] else f"Addressing: VLAN id mapped to the third octet inside {base}.")


def finalize(it):
    """Sanitise intent, resolve device constraints, build the addressing plan and the uplink."""
    it["device"] = it["device"] if it["device"] in DEFAULT_HOST else "router"
    host = re.sub(r"[^A-Za-z0-9-]", "", str(it.get("hostname") or ""))[:63]
    it["hostname"] = host if host[:1].isalpha() else DEFAULT_HOST[it["device"]]
    vlans, names = [], set()
    for v in it["vlans"]:
        try:
            vid = int(v["id"])
        except (KeyError, TypeError, ValueError):
            continue
        if any(x["id"] == vid for x in vlans):
            continue
        name = re.sub(r"[^A-Za-z0-9_-]", "", str(v.get("name") or ""))[:32].upper() or f"VLAN{vid}"
        name = f"{name}{vid}" if name in names else name
        names.add(name)
        try:
            hosts = max(0, int(v.get("hosts") or 0)) or None
        except (TypeError, ValueError):
            hosts = None
        vlans.append({"id": vid, "name": name, "hosts": hosts})
    it["vlans"] = vlans
    it["dns"] = [d for d in it.get("dns") or [] if valid_ip(str(d))] or ["8.8.8.8"]
    try:
        it["ospf_area"] = max(0, int(it.get("ospf_area") or 0))
    except (TypeError, ValueError):
        it["ospf_area"] = 0
    for k in ("ntp_server", "syslog_server"):
        it[k] = it.get(k) if it.get(k) and valid_ip(str(it[k])) else None

    if it["nat"] and it["device"] == "l3switch":
        it["device"] = "router"
        if it["hostname"] == DEFAULT_HOST["l3switch"]:
            it["hostname"] = DEFAULT_HOST["router"]
        it["notes"].append("NAT requested: switched device to router (L3 switches generally lack NAT).")
    plan_addresses(it)
    if it["qos"] or it["ospf"] or it["nat"]:
        if it["nat"]:
            wan, peer = ipaddress.ip_interface("203.0.113.2/30"), "203.0.113.1"
        else:
            used = [ipaddress.ip_network(v["net"]) for v in it["vlans"]]
            net = next((n for n in map(ipaddress.ip_network, WAN_CANDIDATES) if not any(n.overlaps(u) for u in used)),
                       ipaddress.ip_network(WAN_CANDIDATES[-1]))
            wan, peer = ipaddress.ip_interface(f"{net.network_address + 1}/{net.prefixlen}"), str(net.network_address + 2)
        it["wan"] = {"if": "GigabitEthernet0/1", "ip": str(wan.ip), "mask": str(wan.netmask), "net": str(wan.network),
                     "wildcard": str(wan.hostmask), "peer": peer, "nat": it["nat"]}
    else:
        it["wan"] = None
    if it["acl"] and not any(v["name"] == "GUEST" for v in it["vlans"]) and it["vlans"]:
        it["notes"].append("ACL requested without a GUEST VLAN: restricting the last VLAN by default.")
    if it["ntp"] and not it["ntp_server"]:
        it["notes"].append(f"No NTP server given: using documentation address {NTP_PLACEHOLDER}; replace it.")
    if it["syslog"] and not it["syslog_server"]:
        it["notes"].append(f"No syslog server given: using documentation address {SYSLOG_PLACEHOLDER}; replace it.")
    return it


# ----------------------------------------------------------------------------------------
# 3. Generator (every emitted line carries a provenance tag -> retrieved KB entry)
# ----------------------------------------------------------------------------------------
def generate(it):
    L = []

    def add(s, k):
        L.append((s, k))

    sw = it["device"] == "l3switch"
    lan = (lambda v: f"Vlan{v['id']}") if sw else (lambda v: f"GigabitEthernet0/0.{v['id']}")
    net = lambda v: ipaddress.ip_network(v["net"]).network_address
    addr = "KB-ADDR" if it.get("vlsm") else "KB-VLAN"
    area, wan = it["ospf_area"], it["wan"]
    guest = None
    if it["acl"] and it["vlans"]:
        guest = next((v for v in it["vlans"] if v["name"] == "GUEST"), it["vlans"][-1])

    # baseline hardening
    add(f"hostname {it['hostname']}", "KB-BASE")
    add("no ip domain-lookup", "KB-BASE")
    add("ip domain-name lab.local", "KB-BASE")
    add("service password-encryption", "KB-BASE")
    add("security passwords min-length 10", "KB-BASE")
    add("enable secret CHANGE_ME_Str0ng", "KB-BASE")
    add("username admin secret CHANGE_ME_Str0ng", "KB-BASE")
    add("crypto key generate rsa modulus 2048", "KB-BASE")
    add("ip ssh version 2", "KB-BASE")
    add("no ip http server", "KB-BASE")
    add("no ip http secure-server", "KB-BASE")
    add("login block-for 120 attempts 3 within 60", "KB-BASE")
    add("banner motd ^Authorized access only^", "KB-BASE")
    if it["ntp"] or it["syslog"]:
        add("service timestamps log datetime msec", "KB-MGMT")
    if sw and it["vlans"]:
        add("ip routing", "KB-VLAN")
    if it["ipv6"]:
        add("ipv6 unicast-routing", "KB-IPV6")
    if sw:
        for v in it["vlans"]:
            add(f"vlan {v['id']}", "KB-VLAN")
            add(f" name {v['name']}", "KB-VLAN")

    # LAN-facing interfaces
    if not sw and it["vlans"]:
        add("interface GigabitEthernet0/0", "KB-VLAN")
        add(" description Trunk to access switch", "KB-VLAN")
        add(" no shutdown", "KB-VLAN")
    for v in it["vlans"]:
        add(f"interface {lan(v)}", "KB-VLAN")
        if not sw:
            add(f" encapsulation dot1Q {v['id']}", "KB-VLAN")
        add(f" description {v['name']} gateway", "KB-VLAN")
        add(f" ip address {v['gw']} {v['mask']}", addr)
        if it["nat"]:
            add(" ip nat inside", "KB-NAT")
        if guest is v:
            add(" ip access-group GUEST-RESTRICT in", "KB-ACL")
        if it["ipv6"]:
            add(f" ipv6 address 2001:DB8:{v['id']}::1/64", "KB-IPV6")
            if it["ospf"]:
                add(f" ipv6 ospf 1 area {area}", "KB-OSPF")
        if sw:
            add(" no shutdown", "KB-VLAN")

    # WAN / uplink
    if wan:
        add(f"interface {wan['if']}", "KB-VLAN")
        add(" description Uplink / WAN", "KB-VLAN")
        if sw:
            add(" no switchport", "KB-VLAN")
        add(f" ip address {wan['ip']} {wan['mask']}", "KB-NAT" if wan["nat"] else "KB-OSPF")
        if wan["nat"]:
            add(" ip nat outside", "KB-NAT")
        if it["qos"]:
            add(" service-policy output WAN-QOS", "KB-QOS")
        if it["ipv6"]:
            add(" ipv6 address 2001:DB8:FF::1/64", "KB-IPV6")
            if it["ospf"]:
                add(f" ipv6 ospf 1 area {area}", "KB-OSPF")
        add(" no shutdown", "KB-VLAN")

    # DHCP
    if it["dhcp"]:
        for v in it["vlans"]:
            last = f" {net(v) + v['reserved']}" if v["reserved"] > 1 else ""
            add(f"ip dhcp excluded-address {v['gw']}{last}", "KB-DHCP")
        for v in it["vlans"]:
            add(f"ip dhcp pool {v['name']}", "KB-DHCP")
            add(f" network {net(v)} {v['mask']}", "KB-DHCP")
            add(f" default-router {v['gw']}", "KB-DHCP")
            add(" dns-server " + " ".join(it["dns"]), "KB-DHCP")
            add(" lease 3", "KB-DHCP")

    # OSPF
    if it["ospf"]:
        add("router ospf 1", "KB-OSPF")
        add(" router-id 1.1.1.1", "KB-OSPF")
        for v in it["vlans"]:
            add(f" network {net(v)} {v['wildcard']} area {area}", "KB-OSPF")
        if wan and not wan["nat"]:
            add(f" network {ipaddress.ip_network(wan['net']).network_address} {wan['wildcard']} area {area}", "KB-OSPF")
        for v in it["vlans"]:
            add(f" passive-interface {lan(v)}", "KB-OSPF")
        if it["nat"]:
            add(" default-information originate", "KB-OSPF")
        if it["ipv6"]:
            add("ipv6 router ospf 1", "KB-OSPF")
            add(" router-id 1.1.1.1", "KB-OSPF")

    # NAT
    if it["nat"]:
        add("ip access-list standard NAT-INSIDE", "KB-NAT")
        for v in it["vlans"]:
            add(f" permit {net(v)} {v['wildcard']}", "KB-NAT")
        add(f"ip nat inside source list NAT-INSIDE interface {wan['if']} overload", "KB-NAT")
        add(f"ip route 0.0.0.0 0.0.0.0 {wan['peer']}", "KB-NAT")

    # ACL
    if guest:
        add("ip access-list extended GUEST-RESTRICT", "KB-ACL")
        for v in it["vlans"]:
            if v is not guest:
                add(f" deny ip {net(guest)} {guest['wildcard']} {net(v)} {v['wildcard']}", "KB-ACL")
        add(f" deny tcp {net(guest)} {guest['wildcard']} any eq 22", "KB-ACL")
        add(" permit ip any any", "KB-ACL")

    # QoS
    if it["qos"]:
        add("class-map match-any VOICE", "KB-QOS")
        add(" match dscp ef", "KB-QOS")
        add("class-map match-any VIDEO", "KB-QOS")
        add(" match dscp af41", "KB-QOS")
        add("policy-map WAN-QOS", "KB-QOS")
        add(" class VOICE", "KB-QOS")
        add("  priority percent 20", "KB-QOS")
        add(" class VIDEO", "KB-QOS")
        add("  bandwidth percent 30", "KB-QOS")
        add(" class class-default", "KB-QOS")
        add("  fair-queue", "KB-QOS")

    # management plane
    if it["ntp"]:
        add(f"ntp server {it['ntp_server'] or NTP_PLACEHOLDER}", "KB-MGMT")
    if it["syslog"]:
        add(f"logging host {it['syslog_server'] or SYSLOG_PLACEHOLDER}", "KB-MGMT")
        add("logging trap informational", "KB-MGMT")

    add("line con 0", "KB-BASE")
    add(" exec-timeout 5 0", "KB-BASE")
    add(" logging synchronous", "KB-BASE")
    add(" login local", "KB-BASE")
    add("line vty 0 4", "KB-BASE")
    add(" login local", "KB-BASE")
    add(" transport input ssh", "KB-BASE")
    add(" exec-timeout 5 0", "KB-BASE")
    return L


FAULTS = ("dropped 'ip routing', 'service password-encryption', 'ipv6 unicast-routing' and 'login block-for'; "
          "VTY opened to Telnet; first DHCP pool given a wrong default-router; first OSPF network statement removed")


def inject_faults(lines):
    """Simulate a faulty LLM draft: missing globals, Telnet, a wrong DHCP gateway and an OSPF coverage hole."""
    drop = {"ip routing", "service password-encryption", "ipv6 unicast-routing",
            "login block-for 120 attempts 3 within 60"}
    out = [l.replace("transport input ssh", "transport input all") for l in lines if l not in drop]
    gw = next((i for i, l in enumerate(out) if l.startswith(" default-router ")), None)
    if gw is not None:
        out[gw] = f" default-router {ipaddress.ip_address(out[gw].split()[1]) + 1}"
    ospf = next((i for i, l in enumerate(out) if l == "router ospf 1"), None)
    if ospf is not None:
        net = next((i for i in range(ospf + 1, len(out)) if out[i].startswith(" network ")), None)
        if net is not None:
            del out[net]
    return out


# ----------------------------------------------------------------------------------------
# 4. Deterministic validator: syntax grammar, semantic consistency, security compliance
# ----------------------------------------------------------------------------------------
IGNORE = r"!.*|end|version \S+|Building configuration.*|Current configuration.*|boot-(start|end)-marker"
HEADERS = [
    (r"interface \S+", "if"), (r"vlan \d+", "vlan"), (r"ip dhcp pool \S+", "dhcp"),
    (r"router ospf \d+", "ospf"), (r"ipv6 router ospf \d+", "ospf6"),
    (r"ip access-list (standard|extended) \S+", "acl"), (r"class-map( match-(any|all))? \S+", "cmap"),
    (r"policy-map \S+", "pmap"), (r"line (vty \d+ \d+|con 0|aux 0)", "line"),
]
GLOBAL = [
    r"hostname \S+", r"no ip domain-lookup", r"ip domain[- ]name \S+", r"(no )?service password-encryption",
    r"enable secret( \d)? \S+", r"enable password( \d)? \S+", r"username \S+ (privilege \d+ )?(secret|password)( \d)? \S+",
    r"crypto key generate rsa( general-keys)?( modulus \d+)?", r"ip ssh version [12]", r"ip ssh (time-out|authentication-retries) \d+",
    r"(no )?ip http (secure-)?server", r"banner (motd|login|exec) .+", r"(no )?ip routing", r"ip cef", r"(no )?ipv6 cef",
    rf"ip dhcp excluded-address {IP}( {IP})?", rf"ip route {IP} {IP} (\S+)( \d+)?", rf"ip default-gateway {IP}",
    r"ip nat inside source list \S+ interface \S+ overload", r"(no )?ipv6 unicast-routing",
    r"security passwords min-length \d+", r"login block-for \d+ attempts \d+ within \d+",
    r"service timestamps (log|debug) (datetime|uptime)( msec)?( localtime)?( show-timezone)?",
    r"(no )?service (pad|tcp-keepalives-in|tcp-keepalives-out|dhcp|config)", rf"ntp server {IP}( prefer)?",
    rf"logging (host )?{IP}", r"logging (trap|buffered|console) \S+( \S+)?", rf"ip name-server {IP}( {IP})*",
    r"access-list \d+ (permit|deny|remark) .+", r"snmp-server community \S+( (RO|RW))?( \S+)?",
    r"(no )?cdp run", r"spanning-tree (mode \S+|extend system-id|vlan .+)", r"vtp (mode|domain) \S+",
    r"clock timezone .+", r"(no )?aaa new-model", r"license udi .+", r"no ip source-route",
]
SUB = {
    "if": [r"description .+", r"encapsulation dot1Q \d+( native)?", rf"ip address {IP} {IP}( secondary)?",
           r"ip address dhcp", r"no ip address", r"ip nat (inside|outside)", r"ip access-group \S+ (in|out)",
           r"service-policy (input|output) \S+", r"no shutdown", r"shutdown", r"no switchport",
           r"switchport( .+)?", r"spanning-tree .+", r"duplex (auto|full|half)", r"speed (auto|\d+)",
           rf"ip helper-address {IP}", r"no ip (proxy-arp|redirects|unreachables)", r"ipv6 address \S+/\d+",
           r"ipv6 enable", rf"ipv6 ospf \d+ area (\d+|{IP})", r"ip ospf .+", r"bandwidth \d+", r"clock rate \d+",
           r"mtu \d+", r"channel-group \d+ mode \S+", r"standby .+", r"no keepalive"],
    "vlan": [r"name \S+"],
    "dhcp": [rf"network {IP} {IP}", rf"network {IP} /\d+", rf"default-router {IP}( {IP})*", rf"dns-server {IP}( {IP})*",
             r"lease \d+( \d+)*", r"domain-name \S+"],
    "ospf": [rf"router-id {IP}", rf"network {IP} {IP} area (\d+|{IP})", r"(no )?passive-interface \S+",
             r"default-information originate( always)?", r"log-adjacency-changes( detail)?", r"auto-cost .+"],
    "ospf6": [rf"router-id {IP}", r"log-adjacency-changes( detail)?", r"(no )?passive-interface \S+"],
    "acl": [rf"(\d+ )?(permit|deny) (ip|tcp|udp|icmp) (any|host {IP}|{IP} {IP}) (any|host {IP}|{IP} {IP})( eq \S+)?",
            rf"(\d+ )?(permit|deny) ({IP} {IP}|host {IP}|{IP}|any)", r"remark .+"],
    "cmap": [r"match (dscp|ip dscp|protocol|access-group) .+"],
    "pmap": [r"class \S+"],
    "pmapclass": [r"priority( percent)? \d+", r"bandwidth( remaining)?( percent)? \d+", r"fair-queue", r"set dscp \S+",
                  r"police .+", r"shape average \d+"],
    "line": [r"(no )?login( local| authentication \S+)?", r"transport input (ssh|telnet|all|none)( (ssh|telnet))?",
             r"transport output .+", r"exec-timeout \d+ \d+", r"logging synchronous", r"password( \d)? \S+",
             r"privilege level \d+", r"stopbits \d+", r"access-class \S+ in", r"history size \d+"],
}
IFNAMES = ["tengigabitethernet", "gigabitethernet", "fastethernet", "ethernet", "serial", "loopback", "vlan",
           "port-channel", "tunnel"]


def ifname(x):
    """Canonical lowercase interface name so 'Gi0/0.10' and 'GigabitEthernet0/0.10' compare equal."""
    m = re.fullmatch(r"([a-z-]+)\s*([\d/.:]+)", x.lower())
    if not m:
        return x.lower()
    return next((full for full in IFNAMES if full.startswith(m.group(1))), m.group(1)) + m.group(2)


def blocks_of(lines, strict=True):
    """Parse into [header, mode, subs, header_line, sub_lines] blocks by indentation; also returns syntax issues.
    strict=False (audit mode) reports commands outside the grammar as INFO instead of syntax errors."""
    issues, blocks, cur, mode, delim = [], [], None, "g", None
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if delim:
            delim = None if delim in s else delim
            continue
        if not s or re.fullmatch(IGNORE, s, re.I):
            continue
        depth = len(raw) - len(raw.lstrip(" "))
        if depth == 0:
            b = re.fullmatch(r"banner (?:motd|login|exec) (\^C|\S)(.*)", s)
            if b and b.group(1) not in b.group(2):
                delim = b.group(1)
            hm = next((m for p, m in HEADERS if re.fullmatch(p, s, re.I)), None)
            if hm:
                mode, cur = hm, [s, hm, [], n, []]
            else:
                known = any(re.fullmatch(p, s, re.I) for p in GLOBAL)
                mode, cur = ("g" if known or strict else "x"), [s, "g", [], n, []]
                if not known:
                    issues.append(("SYNTAX", "ERROR", f"line {n}: unrecognised/invalid global command '{s}'", n)
                                  if strict else
                                  ("UNKNOWN_CMD", "INFO", f"line {n}: '{s}' is outside the grammar, not checked", n))
            blocks.append(cur)
            continue
        m = mode
        if mode == "pmap":
            m = "pmap" if depth == 1 else "pmapclass"
        if mode != "x" and (mode == "g" or not any(re.fullmatch(p, s, re.I) for p in SUB.get(m, []))):
            issues.append(("SYNTAX", "ERROR", f"line {n}: '{s}' is not valid in '{mode}' mode", n) if strict else
                          ("UNKNOWN_CMD", "INFO", f"line {n}: '{s}' is outside the '{mode}' grammar, not checked", n))
        if cur:
            cur[2].append(s)
            cur[4].append(n)
    return blocks, issues


def valid_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def interfaces(blocks):
    """[(name, ip_interface, subs, header_line)] for every interface with a valid primary IPv4 address."""
    out = []
    for h, m, subs, hn, _ in blocks:
        if m == "if":
            for s in subs:
                a = re.fullmatch(rf"ip address ({IP}) ({IP})", s)
                if a:
                    try:
                        out.append((h[10:], ipaddress.ip_interface(f"{a.group(1)}/{a.group(2)}"), subs, hn))
                    except ValueError:
                        pass
    return out


def dhcp_pools(blocks):
    """[(header, network, gateway, header_line, gateway_line, subs)] for every DHCP pool (network False if invalid)."""
    out = []
    for h, m, subs, hn, sn in blocks:
        if m == "dhcp":
            net, gw, gwn = None, None, None
            for s, n in zip(subs, sn):
                if a := re.fullmatch(rf"network ({IP}) (\S+)", s):
                    try:
                        net = ipaddress.ip_network(f"{a.group(1)}/{a.group(2).lstrip('/')}", strict=False)
                    except ValueError:
                        net = False
                if s.startswith("default-router "):
                    gw, gwn = s.split()[1], n
            out.append((h, net, gw, hn, gwn, subs))
    return out


def ospf_info(blocks):
    """(block, [networks], area, passive set, passive-default) for the first OSPFv2 process, or None."""
    b = next((b for b in blocks if b[1] == "ospf"), None)
    if not b:
        return None
    nets, area, passive, active, pdef = [], None, set(), set(), False
    for s in b[2]:
        if m := re.fullmatch(rf"network ({IP}) ({IP}) area (\S+)", s):
            try:
                nets.append(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
            except ValueError:
                pass
            area = m.group(3) if area is None else area
        if s == "passive-interface default":
            pdef = True
        elif m := re.fullmatch(r"(no )?passive-interface (\S+)", s):
            (active if m.group(1) else passive).add(ifname(m.group(2)))
    return b, nets, area or "0", passive, active, pdef


def validate(lines, strict=True):
    blocks, issues = blocks_of(lines, strict)
    E = lambda c, m, n=None: issues.append((c, "ERROR", m, n))
    W = lambda c, m, n=None: issues.append((c, "WARN", m, n))
    text = [b[0] for b in blocks]
    first = lambda pre: next((b[3] for b in blocks if b[0].startswith(pre)), None)
    allsubs = [(b[0], s, n) for b in blocks for s, n in zip(b[2], b[4])]
    glob = " | ".join(text)

    # IP validity + interface networks
    ids = []
    for h, m, subs, hn, sn in blocks:
        if m == "vlan":
            vid = int(h.split()[1])
            if not 1 <= vid <= 4094 or 1002 <= vid <= 1005:
                E("VLAN_RANGE", f"VLAN {vid} outside usable range 1-4094 (1002-1005 reserved)", hn)
            if vid in ids:
                E("VLAN_DUP", f"VLAN {vid} defined twice", hn)
            ids.append(vid)
        if m == "if":
            for s, n in zip(subs, sn):
                a = re.fullmatch(rf"ip address ({IP}) ({IP})( secondary)?", s)
                if a:
                    try:
                        i = ipaddress.ip_interface(f"{a.group(1)}/{a.group(2)}")
                        if i.network.prefixlen < 31 and i.ip in (i.network.network_address, i.network.broadcast_address):
                            E("BAD_IP", f"{h}: {i.ip} is the network/broadcast address of {i.network}", n)
                    except ValueError:
                        E("BAD_IP", f"{h}: invalid address/mask '{s}'", n)
                a6 = re.fullmatch(r"ipv6 address (\S+)/(\d+)", s)
                if a6 and not valid_ip(a6.group(1)):
                    E("BAD_IPV6", f"{h}: invalid IPv6 address '{s}'", n)
            if "shutdown" in subs and any(s.startswith("ip address ") for s in subs):
                W("IF_SHUTDOWN", f"{h} has an IP address but is administratively shut down", hn)
    ifs = interfaces(blocks)
    for i, (n1, a, _, _) in enumerate(ifs):
        for n2, b, _, hn in ifs[i + 1:]:
            if a.network.overlaps(b.network):
                E("SUBNET_OVERLAP", f"{n1} {a.network} overlaps {n2} {b.network}", hn)

    # L3 switch checks
    ospf = ospf_info(blocks)
    svis = [b for b in blocks if b[1] == "if" and re.fullmatch(r"interface vlan\d+", b[0], re.I)]
    for b in svis:
        vid = int(re.sub(r"\D", "", b[0]))
        if vid != 1 and vid not in ids and (ids or strict):
            E("SVI_NO_VLAN", f"{b[0]} has no matching 'vlan {vid}'", b[3])
    routed = [b for b in blocks if b[1] == "if" and any(s.startswith("ip address ") for s in b[2])
              and (b in svis or "no switchport" in b[2])]
    if svis and (len(routed) >= 2 or (routed and ospf)) and "ip routing" not in text:
        E("NO_IP_ROUTING", "SVIs configured but 'ip routing' missing: no inter-VLAN routing")

    # DHCP consistency
    pools = dhcp_pools(blocks)
    for h, net, gw, hn, gwn, subs in pools:
        if not net:
            E("DHCP_NO_NET", f"{h}: missing or invalid network", hn)
            continue
        match = [i for i in ifs if i[1].network == net]
        if not match:
            (E if strict else W)("DHCP_NO_IFACE", f"{h}: no local interface on {net}", hn)
        elif gw and str(match[0][1].ip) != gw:
            E("DHCP_GW_MISMATCH", f"{h}: default-router {gw} != interface IP {match[0][1].ip}", gwn)
        if not gw:
            W("DHCP_NO_GW", f"{h}: no default-router", hn)
        if not any(s.startswith("dns-server") for s in subs):
            W("DHCP_NO_DNS", f"{h}: clients receive no DNS server", hn)

    # OSPF coverage + passive LAN interfaces
    if ospf:
        b, nets, _, passive, active, pdef = ospf
        for s, n in zip(b[2], b[4]):
            m = re.fullmatch(rf"network ({IP}) ({IP}) area \S+", s)
            if m:
                try:
                    ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
                except ValueError:
                    E("OSPF_WILDCARD", f"invalid wildcard in '{s}'", n)
        lan = {p[1] for p in pools if p[1]}
        for n, a, subs, hn in ifs:
            if "ip nat outside" in subs:
                continue
            if not any(a.ip in x for x in nets):
                E("OSPF_NOT_ADVERTISED", f"{n} ({a.ip}) not covered by any OSPF network statement", hn)
            elif a.network in lan and not (ifname(n) in passive or (pdef and ifname(n) not in active)):
                W("OSPF_HELLO_ON_LAN", f"{n} serves DHCP clients but is not passive: OSPF hellos leak to hosts", hn)
        if not any(s.startswith("router-id") for s in b[2]):
            W("OSPF_NO_RID", "OSPF router-id not set", b[3])

    # ACL
    acl_line = {b[0].split()[3]: b[3] for b in blocks if b[1] == "acl"}
    for b in blocks:
        if m := re.match(r"access-list (\d+) ", b[0]):
            acl_line.setdefault(m.group(1), b[3])
    applied = {}
    for _, s, n in allsubs:
        if m := re.fullmatch(r"ip access-group (\S+) (?:in|out)|access-class (\S+) in", s):
            applied.setdefault(m.group(1) or m.group(2), n)
    nat_acls = {m.group(1) for t in text if (m := re.match(r"ip nat inside source list (\S+)", t))}
    for a in applied.keys() - acl_line.keys():
        E("ACL_UNDEFINED", f"ACL '{a}' applied but not defined", applied[a])
    for a in acl_line.keys() - applied.keys() - nat_acls:
        W("ACL_NOT_APPLIED", f"ACL '{a}' defined but never applied", acl_line[a])

    # NAT
    nat = re.search(r"ip nat inside source list (\S+) interface", glob)
    if nat:
        nn = first("ip nat inside source")
        if nat.group(1) not in acl_line:
            E("NAT_ACL_UNDEFINED", f"NAT references undefined ACL '{nat.group(1)}'", nn)
        if not any(s == "ip nat inside" for _, s, _ in allsubs) or not any(s == "ip nat outside" for _, s, _ in allsubs):
            E("NAT_ROLES", "NAT needs at least one 'ip nat inside' and one 'ip nat outside' interface", nn)
        if not any(t.startswith("ip route 0.0.0.0") for t in text):
            W("NO_DEFAULT_ROUTE", "NAT configured without a default route", nn)

    # QoS
    cmaps = {b[0].split()[-1] for b in blocks if b[1] == "cmap"}
    pmaps = {b[0].split()[-1] for b in blocks if b[1] == "pmap"}
    for b in blocks:
        if b[1] == "pmap":
            for s, n in zip(b[2], b[4]):
                if s.startswith("class ") and s.split()[1] not in cmaps | {"class-default"}:
                    E("QOS_CLASS_UNDEFINED", f"policy-map references undefined class-map '{s.split()[1]}'", n)
    for _, s, n in allsubs:
        m = re.fullmatch(r"service-policy (?:input|output) (\S+)", s)
        if m and m.group(1) not in pmaps:
            E("QOS_POLICY_UNDEFINED", f"service-policy references undefined policy-map '{m.group(1)}'", n)

    # IPv6
    if any(s.startswith("ipv6 address") for _, s, _ in allsubs) and "ipv6 unicast-routing" not in text:
        E("NO_IPV6_ROUTING", "IPv6 addresses configured but 'ipv6 unicast-routing' missing")

    # Security compliance
    if "service password-encryption" not in text:
        W("NO_PWD_ENC", "service password-encryption missing", first("no service password-encryption"))
    if "ip ssh version 2" not in text:
        W("NO_SSH_V2", "SSH version 2 not enforced", first("ip ssh version 1"))
    if "no ip http server" not in text or "ip http server" in text:
        W("NO_HTTP_OFF", "HTTP server not disabled", first("ip http server"))
    if not any(t.startswith("enable secret") for t in text):
        W("NO_ENABLE_SECRET", "enable secret missing")
    if n := first("enable password"):
        W("WEAK_ENABLE_PASSWORD", "'enable password' is stored with weak or no encryption; use 'enable secret'", n)
    for b in blocks:
        if re.fullmatch(r"username \S+ (privilege \d+ )?password .*", b[0]):
            W("PLAINTEXT_USER", f"user '{b[0].split()[1]}' uses reversible 'password'; use 'secret'", b[3])
        if m := re.fullmatch(r"snmp-server community (\S+)(?: (RO|RW))?.*", b[0], re.I):
            if m.group(1).lower() in ("public", "private") or (m.group(2) or "").upper() == "RW":
                W("SNMP_COMMUNITY", f"SNMP community '{m.group(1)}' is a default or read-write string", b[3])
    if not any(t.startswith("login block-for") for t in text):
        W("NO_LOGIN_BLOCK", "no brute-force protection ('login block-for')")
    users = any(t.startswith("username ") for t in text)
    for b in blocks:
        if b[1] != "line":
            continue
        tin = next(((s, n) for s, n in zip(b[2], b[4]) if s.startswith("transport input")), None)
        if tin and re.search(r"\b(telnet|all)\b", tin[0]):
            W("TELNET_ENABLED", f"{b[0]} allows Telnet; restrict to SSH", tin[1])
        if b[0].startswith("line vty"):
            if not tin:
                W("VTY_TRANSPORT_DEFAULT", f"{b[0]}: no 'transport input' (IOS default can allow Telnet)", b[3])
            if "no login" in b[2]:
                E("VTY_OPEN", f"{b[0]}: 'no login' accepts remote sessions without authentication", b[3])
            elif not any(re.fullmatch(r"login( local| authentication \S+)?", s) for s in b[2]):
                W("VTY_NO_LOGIN", f"{b[0]}: no login method, remote access is refused or unauthenticated", b[3])
        if "login local" in b[2] and not users:
            E("LOGIN_LOCAL_NO_USER", f"{b[0]} uses 'login local' but no local username exists", b[3])
        for s, n in zip(b[2], b[4]):
            if s == "exec-timeout 0 0":
                W("EXEC_TIMEOUT_DISABLED", f"{b[0]}: idle sessions never time out", n)
    return issues


# code -> (category, how to fix)
CHECKS = {
    "SYNTAX": ("syntax", "Fix the command spelling or move it under the right configuration mode."),
    "UNKNOWN_CMD": ("syntax", "Outside the validator grammar; review this command manually."),
    "VLAN_RANGE": ("addressing", "Use VLAN IDs 2-1001 or 1006-4094."),
    "VLAN_DUP": ("addressing", "Remove the duplicate VLAN definition."),
    "BAD_IP": ("addressing", "Use a host address (not the network/broadcast) with a contiguous mask."),
    "BAD_IPV6": ("addressing", "Check the IPv6 address and prefix length."),
    "SUBNET_OVERLAP": ("addressing", "Give every interface its own non-overlapping subnet."),
    "SVI_NO_VLAN": ("addressing", "Create the VLAN with 'vlan <id>' so the SVI can come up."),
    "IF_SHUTDOWN": ("addressing", "Use 'no shutdown' if this interface should forward traffic."),
    "NO_IP_ROUTING": ("routing", "Add 'ip routing' so the switch routes between SVIs."),
    "OSPF_WILDCARD": ("routing", "Use a contiguous wildcard mask such as 0.0.0.255."),
    "OSPF_NOT_ADVERTISED": ("routing", "Add a matching 'network <net> <wildcard> area <n>' statement."),
    "OSPF_NO_RID": ("routing", "Set 'router-id' so the OSPF ID stays stable."),
    "OSPF_HELLO_ON_LAN": ("routing", "Make user-facing interfaces passive so hosts cannot form adjacencies."),
    "NO_IPV6_ROUTING": ("routing", "Add 'ipv6 unicast-routing'."),
    "NO_DEFAULT_ROUTE": ("routing", "Add 'ip route 0.0.0.0 0.0.0.0 <ISP gateway>'."),
    "DHCP_NO_NET": ("services", "Add 'network <net> <mask>' to the pool."),
    "DHCP_NO_IFACE": ("services", "The pool must match a local interface subnet, or be served through a DHCP relay."),
    "DHCP_GW_MISMATCH": ("services", "Set default-router to the interface IP of that subnet."),
    "DHCP_NO_GW": ("services", "Add 'default-router <gateway>'."),
    "DHCP_NO_DNS": ("services", "Add 'dns-server <ip>' so clients can resolve names."),
    "ACL_UNDEFINED": ("services", "Define the ACL or remove the reference."),
    "ACL_NOT_APPLIED": ("services", "Apply it with 'ip access-group' or delete it."),
    "NAT_ACL_UNDEFINED": ("services", "Define the ACL that selects the inside addresses."),
    "NAT_ROLES": ("services", "Mark LAN interfaces 'ip nat inside' and the uplink 'ip nat outside'."),
    "QOS_CLASS_UNDEFINED": ("services", "Define the class-map or remove it from the policy."),
    "QOS_POLICY_UNDEFINED": ("services", "Define the policy-map or remove the service-policy."),
    "NO_PWD_ENC": ("security", "Add 'service password-encryption'."),
    "NO_SSH_V2": ("security", "Add 'ip ssh version 2'."),
    "NO_HTTP_OFF": ("security", "Add 'no ip http server'."),
    "NO_ENABLE_SECRET": ("security", "Add 'enable secret <strong-secret>'."),
    "WEAK_ENABLE_PASSWORD": ("security", "Remove 'enable password' and use 'enable secret'."),
    "PLAINTEXT_USER": ("security", "Use 'username <name> secret <password>'."),
    "SNMP_COMMUNITY": ("security", "Use a non-default read-only community, or better, SNMPv3."),
    "NO_LOGIN_BLOCK": ("security", "Add 'login block-for 120 attempts 3 within 60'."),
    "TELNET_ENABLED": ("security", "Use 'transport input ssh'."),
    "VTY_TRANSPORT_DEFAULT": ("security", "Add 'transport input ssh' to the VTY lines."),
    "VTY_NO_LOGIN": ("security", "Add 'login local' to the VTY lines."),
    "VTY_OPEN": ("security", "Replace 'no login' with 'login local'."),
    "LOGIN_LOCAL_NO_USER": ("security", "Create a local user: 'username <name> secret <password>'."),
    "EXEC_TIMEOUT_DISABLED": ("security", "Use 'exec-timeout 5 0'."),
}
CATEGORIES = [("syntax", "Syntax"), ("addressing", "Addressing"), ("routing", "Routing"), ("services", "Services"),
              ("security", "Security")]

GLOBAL_FIXES = {  # code -> global line inserted after hostname (or swapped in for a contradicting line)
    "NO_IP_ROUTING": "ip routing", "NO_PWD_ENC": "service password-encryption", "NO_SSH_V2": "ip ssh version 2",
    "NO_HTTP_OFF": "no ip http server", "NO_IPV6_ROUTING": "ipv6 unicast-routing",
    "NO_ENABLE_SECRET": "enable secret CHANGE_ME_Str0ng", "NO_LOGIN_BLOCK": "login block-for 120 attempts 3 within 60",
    "LOGIN_LOCAL_NO_USER": "username admin secret CHANGE_ME_Str0ng",
}


def _pad(l):
    return l[:len(l) - len(l.lstrip(" "))] or " "


def fix_dhcp_gw(out):
    blocks, _ = blocks_of(out, False)
    ifs, log = interfaces(blocks), []
    for h, net, gw, _, gwn, _ in dhcp_pools(blocks):
        match = [i for i in ifs if net and i[1].network == net]
        if match and gw and gwn and str(match[0][1].ip) != gw:
            out[gwn - 1] = f"{_pad(out[gwn - 1])}default-router {match[0][1].ip}"
            log.append(("DHCP_GW_MISMATCH", f"{h}: default-router {gw} -> {match[0][1].ip}"))
    return out, log


def fix_ospf_cover(out):
    blocks, _ = blocks_of(out, False)
    info = ospf_info(blocks)
    if not info:
        return out, []
    b, nets, area, *_ = info
    last = max([b[3]] + [n for s, n in zip(b[2], b[4]) if s.startswith("network ")])
    add = []
    for name, a, subs, _ in interfaces(blocks):
        line = f" network {a.network.network_address} {a.network.hostmask} area {area}"
        if "ip nat outside" not in subs and not any(a.ip in x for x in nets) and line not in add:
            add.append(line)
    out[last:last] = add
    return out, [("OSPF_NOT_ADVERTISED", f"added '{l.strip()}' to {b[0]}") for l in add]


def fix_ospf_passive(out):
    blocks, _ = blocks_of(out, False)
    info = ospf_info(blocks)
    if not info:
        return out, []
    b, nets, _, passive, active, pdef = info
    lan = {p[1] for p in dhcp_pools(blocks) if p[1]}
    add = [f" passive-interface {n}" for n, a, subs, _ in interfaces(blocks)
           if a.network in lan and any(a.ip in x for x in nets)
           and not (ifname(n) in passive or (pdef and ifname(n) not in active))]
    last = max([b[3]] + b[4])
    out[last:last] = add
    return out, [("OSPF_HELLO_ON_LAN", f"added '{l.strip()}'") for l in add]


def fix_ospf_rid(out):
    """Pin the router ID to the value IOS would auto-select (highest interface IPv4), so nothing changes today."""
    blocks, _ = blocks_of(out, False)
    info, ips = ospf_info(blocks), [a.ip for _, a, _, _ in interfaces(blocks)]
    if not info or not ips:
        return out, []
    hn = info[0][3]
    out.insert(hn, f" router-id {max(ips)}")
    return out, [("OSPF_NO_RID", f"{info[0][0]}: pinned router-id {max(ips)} (the current auto-selected ID)")]


def fix_vty(out):
    blocks, _ = blocks_of(out, False)
    log = []
    for b in sorted((b for b in blocks if b[0].startswith("line vty")), key=lambda b: -b[3]):
        subs = dict(zip(b[2], b[4]))
        add = []
        if "no login" in subs:
            out[subs["no login"] - 1] = " login local"
            log.append(("VTY_OPEN", f"{b[0]}: 'no login' -> 'login local'"))
        elif not any(re.fullmatch(r"login( local| authentication \S+)?", s) for s in subs):
            add.append(" login local")
            log.append(("VTY_NO_LOGIN", f"{b[0]}: added 'login local'"))
        if not any(s.startswith("transport input") for s in subs):
            add.append(" transport input ssh")
            log.append(("VTY_TRANSPORT_DEFAULT", f"{b[0]}: added 'transport input ssh'"))
        last = max([b[3]] + b[4])
        out[last:last] = add
    return out, log


def fix_telnet(out):
    log = []
    for i, l in enumerate(out):
        if l.strip().startswith("transport input") and re.search(r"\b(telnet|all)\b", l):
            out[i] = f"{_pad(l)}transport input ssh"
            log.append(("TELNET_ENABLED", f"line {i + 1}: '{l.strip()}' -> 'transport input ssh'"))
    return out, log


def fix_exec_timeout(out):
    log = []
    for i, l in enumerate(out):
        if l.strip() == "exec-timeout 0 0":
            out[i] = f"{_pad(l)}exec-timeout 5 0"
            log.append(("EXEC_TIMEOUT_DISABLED", f"line {i + 1}: exec-timeout 0 0 -> 5 0"))
    return out, log


def fix_plain_user(out):
    log = []
    for i, l in enumerate(out):
        if m := re.fullmatch(r"(username \S+(?: privilege \d+)?) password (?:0 )?(\S+)", l):
            out[i] = f"{m.group(1)} secret {m.group(2)}"
            log.append(("PLAINTEXT_USER", f"line {i + 1}: '{m.group(1)}' now stored as a hashed secret"))
    return out, log


def fix_enable_password(out):
    keep = [l for l in out if not l.startswith("enable password")]
    if len(keep) == len(out):
        return out, []
    return keep, [("WEAK_ENABLE_PASSWORD", "removed 'enable password' (enable secret takes over)")]


FIXERS = {"DHCP_GW_MISMATCH": fix_dhcp_gw, "OSPF_NOT_ADVERTISED": fix_ospf_cover, "OSPF_HELLO_ON_LAN": fix_ospf_passive,
          "OSPF_NO_RID": fix_ospf_rid,
          "VTY_TRANSPORT_DEFAULT": fix_vty, "VTY_NO_LOGIN": fix_vty, "VTY_OPEN": fix_vty, "TELNET_ENABLED": fix_telnet,
          "EXEC_TIMEOUT_DISABLED": fix_exec_timeout, "PLAINTEXT_USER": fix_plain_user,
          "WEAK_ENABLE_PASSWORD": fix_enable_password}


def repair(lines, issues):
    """Deterministic repair of known failure classes (an LLM repair prompt can be chained for the rest).
    Returns the new lines and [(code, action)]."""
    out, log = list(lines), []
    codes = {i[0] for i in issues}
    hn = next((i for i, l in enumerate(out) if l.startswith("hostname")), None)
    pos = hn + 1 if hn is not None else next(
        (i for i, l in enumerate(out) if l.strip() and not re.fullmatch(IGNORE, l.strip(), re.I)), 0)
    for c in sorted(codes & GLOBAL_FIXES.keys()):
        fix = GLOBAL_FIXES[c]
        neg = {fix[3:] if fix.startswith("no ") else "no " + fix} | ({"ip ssh version 1"} if c == "NO_SSH_V2" else set())
        clash = next((i for i, l in enumerate(out) if l.strip() in neg), None)
        if clash is not None:
            log.append((c, f"replaced '{out[clash].strip()}' with '{fix}'"))
            out[clash] = fix
        else:
            out.insert(pos, fix)
            log.append((c, f"inserted '{fix}'"))
    for fn in dict.fromkeys(FIXERS[c] for c in sorted(codes) if c in FIXERS):
        out, done = fn(out)
        log += done
    return out, log


# ----------------------------------------------------------------------------------------
# 5. Explainer, knowledge-source classifier, topology and verification plan
# ----------------------------------------------------------------------------------------
EXPLAIN = [
    (r"hostname (\S+)", "Sets the device name to {0}."),
    (r"no ip domain-lookup", "Stops the CLI treating mistyped commands as hostnames to resolve."),
    (r"ip domain[- ]name (\S+)", "Sets DNS domain {0}; with the hostname it names the RSA key SSH needs."),
    (r"service password-encryption", "Obfuscates plaintext passwords in the running config."),
    (r"security passwords min-length (\d+)", "Rejects any new password shorter than {0} characters."),
    (r"enable secret .*", "Protects privileged EXEC mode with a hashed secret (change the placeholder!)."),
    (r"enable password .*", "Plain enable password: weak, reversible storage. Prefer 'enable secret'."),
    (r"username (\S+) .*", "Creates local user {0}; used by 'login local' on the console and VTY lines."),
    (r"crypto key generate rsa.*", "Generates the RSA key pair that SSH needs."),
    (r"ip ssh version 2", "Forces SSHv2, which fixes weaknesses in SSHv1."),
    (r"no ip http server|no ip http secure-server", "Disables the web management service to shrink the attack surface."),
    (r"ip http (secure-)?server", "Enables the web management service (larger attack surface)."),
    (r"login block-for (\d+) attempts (\d+) within (\d+)",
     "Blocks logins for {0}s after {1} failed attempts within {2}s (brute-force protection)."),
    (r"banner (motd|login|exec) .*", "Legal warning shown to anyone connecting."),
    (r"service timestamps log datetime.*", "Stamps every log message with the date and time."),
    (r"ip routing", "Enables Layer-3 forwarding on the switch so SVIs can route between VLANs."),
    (r"vlan (\d+)", "Creates VLAN {0} in the VLAN database."),
    (r"name (\S+)", "Names the VLAN {0}."),
    (r"interface Vlan(\d+)", "SVI: the Layer-3 gateway interface for VLAN {0}."),
    (r"interface (\S+)\.(\d+)", "Sub-interface {0}.{1}: router-on-a-stick gateway for VLAN {1}."),
    (r"interface (\S+)", "Enters configuration of interface {0}."),
    (r"description (.+)", "Labels the interface \"{0}\"."),
    (r"encapsulation dot1Q (\d+)", "Tags frames of VLAN {0} with IEEE 802.1Q on this sub-interface."),
    (r"ip address (\S+) (\S+)", "Assigns IPv4 address {0} with mask {1}."),
    (r"no shutdown", "Brings the interface administratively up."),
    (r"shutdown", "Administratively disables the interface."),
    (r"no switchport", "Turns the switch port into a routed (Layer-3) port."),
    (r"switchport mode (\S+)", "Sets the port to {0} mode."),
    (r"switchport access vlan (\d+)", "Places the port in VLAN {0}."),
    (r"no ip address", "No IPv4 address on this interface."),
    (r"ip helper-address (\S+)", "Relays DHCP broadcasts to server {0}."),
    (r"ip dhcp excluded-address (\S+) (\S+)", "Reserves {0}-{1} so DHCP never leases them (gateway/static hosts)."),
    (r"ip dhcp excluded-address (\S+)", "Reserves {0} (the gateway) so DHCP never leases it."),
    (r"ip dhcp pool (\S+)", "Defines DHCP pool {0}."),
    (r"network (\S+) (\S+)", "Leases addresses from {0} mask {1}."),
    (r"default-router (\S+)", "Clients receive {0} as their default gateway."),
    (r"dns-server (.+)", "Clients receive DNS server(s) {0}."),
    (r"lease (\d+)", "Leases last {0} days."),
    (r"router ospf (\d+)", "Starts OSPF process {0}."),
    (r"router-id (\S+)", "Pins the router ID to {0} so it never changes with interface addresses."),
    (r"network (\S+) (\S+) area (\S+)", "Advertises {0} (wildcard {1}) into OSPF area {2}."),
    (r"passive-interface (\S+)", "Stops OSPF hellos on {0} (user-facing) while still advertising its subnet."),
    (r"default-information originate", "Injects a default route into OSPF so neighbours reach the Internet via this router."),
    (r"ipv6 router ospf (\d+)", "Starts OSPFv3 process {0} for IPv6."),
    (r"ip access-list (standard|extended) (\S+)", "Defines {0} ACL {1}."),
    (r"deny ip (\S+) \S+ (\S+) \S+", "Blocks traffic from {0} to {1}."),
    (r"deny tcp (\S+) \S+ any eq 22", "Stops hosts in {0} opening SSH sessions to network devices."),
    (r"permit ip any any", "Allows everything else (ACLs end in an implicit deny)."),
    (r"permit (\S+) (\S+)", "Matches source network {0} (wildcard {1})."),
    (r"access-list (\d+) (permit|deny) (.+)", "Numbered ACL {0}: {1} {2}."),
    (r"ip access-group (\S+) (\S+)", "Applies ACL {0} to inbound/outbound ({1}) traffic on this interface."),
    (r"access-class (\S+) in", "Only hosts permitted by ACL {0} may reach these lines."),
    (r"ip nat inside source list (\S+) interface (\S+) overload", "PAT: translates inside hosts matched by {0} to {1}'s address."),
    (r"ip nat (inside|outside)", "Marks this interface as the NAT {0} side."),
    (r"ip route 0\.0\.0\.0 0\.0\.0\.0 (\S+)", "Default route towards the ISP gateway {0}."),
    (r"ip route (\S+) (\S+) (\S+)", "Static route to {0} {1} via {2}."),
    (r"ip default-gateway (\S+)", "Gateway the device itself uses while IP routing is off."),
    (r"class-map match-any (\S+)", "QoS class {0}, matched by DSCP."),
    (r"match dscp (\S+)", "Matches packets marked DSCP {0}."),
    (r"policy-map (\S+)", "QoS policy {0} (MQC)."),
    (r"class class-default", "Everything not matched by the classes above."),
    (r"class (\S+)", "Actions below apply to class {0}."),
    (r"priority percent (\d+)", "Low-latency queue limited to {0}% of bandwidth (voice)."),
    (r"bandwidth percent (\d+)", "Guarantees {0}% of bandwidth to this class."),
    (r"fair-queue", "Shares the remaining bandwidth fairly between flows."),
    (r"service-policy output (\S+)", "Applies QoS policy {0} to egress traffic."),
    (r"ipv6 unicast-routing", "Enables IPv6 forwarding."),
    (r"ipv6 address (\S+)", "Assigns IPv6 address {0} (2001:DB8::/32 is the documentation prefix)."),
    (r"ipv6 ospf (\d+) area (\S+)", "Enables OSPFv3 process {0} on this interface in area {1}."),
    (r"ntp server (\S+).*", "Synchronises the clock with NTP server {0}."),
    (rf"logging (?:host )?({IP})", "Sends syslog messages to {0}."),
    (r"logging trap (\S+)", "Sends messages of severity '{0}' and above to the syslog server."),
    (r"snmp-server community (\S+) ?(\S*).*", "SNMPv1/v2c community '{0}' {1} (sent in cleartext; prefer SNMPv3)."),
    (r"line con 0", "Configures the console port."),
    (r"line vty (\d+) (\d+)", "Configures remote-access lines {0}-{1}."),
    (r"logging synchronous", "Stops log messages interrupting what you are typing."),
    (r"login local", "Authenticates with the local username database."),
    (r"no login", "No authentication at all on these lines."),
    (r"transport input ssh", "Allows only SSH on the VTY lines (no Telnet)."),
    (r"transport input (.+)", "Allows {0} on the VTY lines."),
    (r"exec-timeout 0 0", "Idle sessions never time out."),
    (r"exec-timeout (\d+) (\d+)", "Logs idle sessions out after {0} min {1} s."),
]


def explain(line):
    s = line.strip()
    for p, t in EXPLAIN:
        m = re.fullmatch(p, s)
        if m:
            return t.format(*[g for g in m.groups() if g is not None])
    return ""


def classify(s, mode):
    """Knowledge-base entry that a command belongs to (used when no generator provenance exists)."""
    w = s.split()
    if mode == "dhcp" or s.startswith("ip dhcp"):
        return "KB-DHCP"
    if mode in ("ospf", "ospf6") or "ospf" in w:
        return "KB-OSPF"
    if mode in ("cmap", "pmap") or s.startswith("service-policy"):
        return "KB-QOS"
    if "nat" in w[:2] or s.startswith("ip route 0.0.0.0"):
        return "KB-NAT"
    if mode == "acl" or s.startswith(("access-list", "ip access-group", "access-class")):
        return "KB-ACL"
    if "ipv6" in s:
        return "KB-IPV6"
    if s.startswith(("ntp", "logging", "service timestamps")) and mode != "line":
        return "KB-MGMT"
    if mode in ("vlan", "if") or s.startswith(("vlan", "ip routing")):
        return "KB-VLAN"
    return "KB-BASE" if s and not s.startswith("!") else ""


def annotate(lines, prov=None):
    """Per-line records for the UI: number, text, knowledge source and explanation."""
    blocks, _ = blocks_of(lines, False)
    mode = {}
    for b in blocks:
        mode[b[3]] = b[1]
        mode.update((n, b[1]) for n in b[4])
    return [{"n": n, "text": l, "src": (prov or {}).get(l) or (classify(l.strip(), mode[n]) if n in mode else ""),
             "why": explain(l) if n in mode else ""} for n, l in enumerate(lines, 1)]


def features_of(blocks):
    text = [b[0] for b in blocks]
    subs = [s for b in blocks for s in b[2]]
    return {
        "switch": any(b[1] == "vlan" or (re.fullmatch(r"interface vlan\d+", b[0], re.I)
                                          and any(s.startswith("ip address ") for s in b[2])) for b in blocks),
        "dhcp": any(b[1] == "dhcp" for b in blocks), "ospf": any(b[1] == "ospf" for b in blocks),
        "ospf6": any(b[1] == "ospf6" for b in blocks),
        "acl": any(s.startswith("ip access-group") for s in subs),
        "nat": any(t.startswith("ip nat inside source") for t in text),
        "qos": any(s.startswith("service-policy") for s in subs),
        "ipv6": "ipv6 unicast-routing" in text or any(s.startswith("ipv6 address") for s in subs),
        "ntp": any(t.startswith("ntp server") for t in text),
        "syslog": any(re.match(rf"logging (host )?{IP}", t) for t in text),
        "ssh": "ip ssh version 2" in text or "transport input ssh" in subs,
        "login_block": any(t.startswith("login block-for") for t in text),
    }


def topology_of(blocks):
    """Device, uplink and LAN segments recovered from the config itself (works for generated and audited)."""
    host = next((b[0].split()[1] for b in blocks if b[0].startswith("hostname ")), "device")
    pools = {p[1] for p in dhcp_pools(blocks) if p[1]}
    info = ospf_info(blocks)
    ospf_nets = info[1] if info else []
    peer = next((m.group(1) for b in blocks if (m := re.fullmatch(rf"ip route 0\.0\.0\.0 0\.0\.0\.0 ({IP})", b[0]))), None)
    segs, uplink, trunk = [], None, None
    for name, a, subs, _ in interfaces(blocks):
        desc = next((s[12:] for s in subs if s.startswith("description ")), "")
        pick = lambda pre: next((s.split()[2] for s in subs if s.startswith(pre) and len(s.split()) > 2), None)
        lan = a.network in pools or any(s.startswith("encapsulation") for s in subs) or name.lower().startswith("vlan")
        if uplink is None and ("ip nat outside" in subs or (not lan and (
                re.search(r"uplink|wan|isp|internet|upstream|hq|core", desc, re.I) or a.network.prefixlen >= 30))):
            uplink = {"if": name, "ip": f"{a.ip}/{a.network.prefixlen}", "peer": peer, "nat": "ip nat outside" in subs,
                      "qos": pick("service-policy"), "v6": pick("ipv6 address"),
                      "ospf": any(a.ip in x for x in ospf_nets)}
            continue
        vid = next((int(s.split()[2]) for s in subs if s.startswith("encapsulation dot1Q")), None)
        if re.fullmatch(r"vlan\d+", name, re.I):
            vid = int(name[4:])
        if "." in name:
            trunk = name.split(".")[0]
        label = re.sub(r"\s*gateway$", "", desc, flags=re.I) or (f"VLAN {vid}" if vid else name)
        segs.append({"vlan": vid, "name": label, "if": name,
                     "net": str(a.network), "gw": str(a.ip), "v6": pick("ipv6 address"), "dhcp": a.network in pools,
                     "acl": pick("ip access-group"), "ospf": any(a.ip in x for x in ospf_nets)})
    sw = any(re.fullmatch(r"vlan\d+", s["if"], re.I) for s in segs)
    return {"hostname": host, "device": "l3switch" if sw else "router", "uplink": uplink, "trunk": trunk,
            "segments": segs}


def verify_plan(blocks):
    """Show commands and client tests that prove the config works in Packet Tracer / GNS3 / CML."""
    f, topo = features_of(blocks), topology_of(blocks)
    segs, up, P = topo["segments"], topo["uplink"], []
    dev = lambda cmd, expect: P.append({"kind": "device", "cmd": cmd, "expect": expect})
    pc = lambda cmd, expect: P.append({"kind": "client", "cmd": cmd, "expect": expect})
    addrs = [f"{s['if']} {s['gw']}" for s in segs[:6]] + ([f"{up['if']} {up['ip'].split('/')[0]}"] if up else [])
    dev("show ip interface brief", "Up/up with the planned addresses: " + (", ".join(addrs) or "none configured"))
    if f["switch"] and segs:
        dev("show vlan brief", "VLANs " + ", ".join(str(s["vlan"]) for s in segs if s["vlan"]) + " exist and are active")
    if segs:
        dev("show ip route connected", f"{len(segs)} connected LAN route(s): " + ", ".join(s["net"] for s in segs[:6]))
    if f["dhcp"]:
        dev("show ip dhcp pool", "One pool per LAN with the expected range and leased-address count")
        dev("show ip dhcp binding", "Client MACs bound to addresses once PCs request DHCP")
    if f["ospf"]:
        dev("show ip ospf neighbor", "FULL adjacency with the upstream router" if up and up["ospf"] else
            "FULL adjacency with every OSPF neighbour")
        dev("show ip protocols", "Advertised networks listed; LAN gateways shown under passive interfaces")
    for acl in dict.fromkeys(s["acl"] for s in segs if s["acl"]):
        dev(f"show access-lists {acl}", "Match counters on the deny lines rise when blocked traffic is tried")
    if f["nat"]:
        dev("show ip nat statistics", f"Inside: LAN interfaces; outside: {up['if'] if up else 'the uplink'}")
        dev("show ip nat translations", "Entries appear after a LAN host pings past the router")
    if f["qos"] and up:
        dev(f"show policy-map interface {up['if']}", "Policy attached outbound; class counters increase under load")
    if f["ipv6"]:
        dev("show ipv6 interface brief", "Each interface lists its 2001:DB8 global address")
        if f["ospf6"]:
            dev("show ipv6 ospf neighbor", "OSPFv3 neighbours FULL")
    if f["ntp"]:
        dev("show ntp associations", "Server listed; '*' marks the synced peer once it is reachable")
    if f["syslog"]:
        dev("show logging", "Logging to the syslog host enabled, trap level informational")
    if f["ssh"]:
        dev("show ip ssh", "SSH Enabled - version 2.0")
    if f["login_block"]:
        dev("show login", "Brute-force blocking policy listed")
    for s in segs[:6]:
        if s["dhcp"]:
            pc(f"ipconfig /renew   (PC in {s['name']})", f"Address inside {s['net']}, gateway {s['gw']}")
        pc(f"ping {s['gw']}   (PC in {s['name']})", "Replies from its gateway")
    open_segs = [s for s in segs if not s["acl"]]
    if len(open_segs) >= 2:
        a, b = open_segs[0], open_segs[1]
        pc(f"ping {b['gw']}   (PC in {a['name']})", "Replies: inter-VLAN routing works")
    for s in segs:
        if s["acl"]:
            for o in [o for o in segs if o is not s][:2]:
                pc(f"ping {o['gw']}   (PC in {s['name']})", f"Expected to fail: ACL {s['acl']} filters this VLAN")
    if f["nat"] and up and up["peer"]:
        pc(f"ping {up['peer']}   (any LAN PC)", "Replies, and a translation appears on the router")
    return P


# ----------------------------------------------------------------------------------------
# 6. Orchestrator
# ----------------------------------------------------------------------------------------
def report(issues):
    e = sum(1 for i in issues if i[1] == "ERROR")
    w = sum(1 for i in issues if i[1] == "WARN")
    return max(0, 100 - 12 * e - 4 * w), e, w


def check_and_repair(lines, strict=True, do_repair=True, passes=3):
    """Validate, then repair and re-validate until clean, nothing more can be fixed, or passes run out."""
    issues = validate(lines, strict)
    draft_issues, history, log = list(issues), [report(issues)[0]], []
    for p in range(1, passes + 1):
        if not do_repair or not any(i[1] != "INFO" for i in issues):
            break
        fixed_lines, fixed = repair(lines, issues)
        if not fixed:
            break
        log += [{"pass": p, "code": c, "action": a} for c, a in fixed]
        lines = fixed_lines
        issues = validate(lines, strict)
        history.append(report(issues)[0])
    return lines, issues, draft_issues, history, log


def fmt(xs):
    return [{"code": c, "severity": s, "message": m, "line": n, "category": CHECKS.get(c, ("other", ""))[0],
             "hint": CHECKS.get(c, ("", ""))[1], "fixable": c in GLOBAL_FIXES or c in FIXERS} for c, s, m, n in xs]


def summary(draft, final):
    count = lambda xs, cat, sev: sum(1 for i in xs if CHECKS.get(i[0], ("other",))[0] == cat and i[1] == sev)
    return [{"id": c, "label": l, "draft_errors": count(draft, c, "ERROR"), "draft_warnings": count(draft, c, "WARN"),
             "errors": count(final, c, "ERROR"), "warnings": count(final, c, "WARN"), "infos": count(final, c, "INFO")}
            for c, l in CATEGORIES]


def diff_of(a, b):
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "equal":
            out += [{"op": " ", "a": i + 1, "b": j + 1, "text": a[i]} for i, j in zip(range(i1, i2), range(j1, j2))]
        else:
            out += [{"op": "-", "a": i + 1, "b": None, "text": a[i]} for i in range(i1, i2)]
            out += [{"op": "+", "a": None, "b": j + 1, "text": b[j]} for j in range(j1, j2)]
    return out


def _result(mode, request, draft, lines, issues, draft_issues, history, log, retrieved, prov, trace, **extra):
    blocks, _ = blocks_of(lines, False)
    recs = annotate(lines, prov)
    score, e, w = report(issues)
    expl = [{"n": r["n"], "cmd": r["text"].strip(), "text": r["why"], "source": r["src"],
             "source_title": KB.get(r["src"], ("",))[0]} for r in recs if r["why"]]
    return {"mode": mode, "request": request, "retrieved": [{"score": s, "id": i, "title": KB[i][0]} for s, i in retrieved],
            "history": history, "repairs": log, "issues": fmt(issues), "draft_issues": fmt(draft_issues),
            "score": score, "errors": e, "warnings": w, "infos": sum(1 for i in issues if i[1] == "INFO"),
            "checks": summary(draft_issues, issues), "config": "\n".join(lines) + "\n",
            "draft_config": "\n".join(draft) + "\n", "lines": recs, "diff": diff_of(draft, lines),
            "explanations": expl, "verify": verify_plan(blocks), "topology": topology_of(blocks),
            "features": features_of(blocks), "trace": trace, "llm": bool(os.environ.get("LLM_BASE_URL")),
            "kb": {k: v[0] for k, v in KB.items()}, **extra}


class Clock:
    def __init__(self):
        self.t, self.trace = time.perf_counter(), []

    def lap(self, stage):
        now = time.perf_counter()
        self.trace.append({"stage": stage, "ms": round((now - self.t) * 1000, 2)})
        self.t = now


def run_pipeline(request, inject_fault=False, options=None):
    """Full pipeline; returns a JSON-serialisable dict (used by CLI and web UI)."""
    clk = Clock()
    it = rule_intent(request)
    feats = [k for k in ("dhcp", "ospf", "nat", "qos", "ipv6", "acl", "ntp", "syslog") if it[k]]
    if it["base"] or any(v["hosts"] for v in it["vlans"]):
        feats.append("subnet vlsm hosts")
    ret = RETRIEVER.search(request + " " + " ".join(feats), k=5)
    clk.lap("retrieve")
    ctx = "\n".join(f"[{i}] {KB[i][0]}: {KB[i][1]}" for _, i in ret)
    if os.environ.get("LLM_BASE_URL"):
        try:
            it = llm_intent(request, ctx, it)
            it["notes"].append("Intent extracted by LLM backend.")
        except Exception as ex:  # never crash the pipeline
            it["notes"].append(f"LLM backend failed ({ex}); used rule-based parser.")
    else:
        it["notes"].append("No LLM configured: using offline rule-based intent parser.")
    clk.lap("intent")
    it = finalize(apply_options(it, options or {}))
    clk.lap("address plan")

    gen = generate(it)
    lines = [l for l, _ in gen]
    if inject_fault:
        lines = inject_faults(lines)
    draft = list(lines)
    clk.lap("generate")
    lines, issues, draft_issues, history, log = check_and_repair(lines)
    clk.lap("validate + repair")
    res = _result("generate", request, draft, lines, issues, draft_issues, history, log, ret, dict(gen), clk.trace,
                  intent=it, faults=FAULTS if inject_fault else None)
    clk.lap("explain + plan")
    return res


def run_audit(text, do_repair=True):
    """Audit an existing config: lenient grammar, same semantic/security checks, optional repair loop."""
    clk = Clock()
    lines = [l.rstrip() for l in text.replace("\r", "").expandtabs(1).split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    if not any(l.strip() for l in lines):
        raise ValueError("Paste a configuration to audit.")
    if len(lines) > 5000:
        raise ValueError("Config too long (max 5000 lines).")
    draft = list(lines)
    lines, issues, draft_issues, history, log = check_and_repair(lines, strict=False, do_repair=do_repair)
    clk.lap("validate + repair")
    blocks, _ = blocks_of(draft, False)
    f = features_of(blocks)
    ret = RETRIEVER.search(" ".join(k for k, v in f.items() if v) + " security hardening", k=5)
    host = next((b[0].split()[1] for b in blocks if b[0].startswith("hostname ")), "config")
    res = _result("audit", f"Audit of {host} ({len(draft)} lines)", draft, lines, issues, draft_issues, history,
                  log, ret, None, clk.trace, intent=None, faults=None)
    clk.lap("explain + plan")
    return res


def write_outputs(r, out):
    os.makedirs(out, exist_ok=True)
    open(f"{out}/config.txt", "w").write(r["config"])
    with open(f"{out}/explained.md", "w") as f:
        f.write(f"# Explained configuration\n\nRequest: {r['request']}\n\n| Line | Command | Explanation | Source |\n"
                "|---|---|---|---|\n")
        for x in r["explanations"]:
            f.write(f"| {x['n']} | `{x['cmd']}` | {x['text']} | {x['source']} {x['source_title']} |\n")
    with open(f"{out}/verify.md", "w") as f:
        f.write(f"# Verification plan\n\nRequest: {r['request']}\n\n")
        for kind, title in (("device", "On the device"), ("client", "From client PCs")):
            f.write(f"## {title}\n\n" + "".join(f"- [ ] `{x['cmd']}` - {x['expect']}\n"
                                                for x in r["verify"] if x["kind"] == kind) + "\n")
    json.dump(r, open(f"{out}/report.json", "w"), indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("request", nargs="?", help="natural-language requirement")
    ap.add_argument("--out", default="output")
    ap.add_argument("--inject-fault", action="store_true", help="simulate a faulty LLM draft to show repair loop")
    ap.add_argument("--device", choices=["router", "l3switch"], help="force the device type")
    ap.add_argument("--hostname", help="override the hostname")
    ap.add_argument("--base", help="base network for the addressing plan, e.g. 10.20.0.0/16")
    ap.add_argument("--dns", help="DNS servers handed out by DHCP, e.g. '1.1.1.1 8.8.8.8'")
    ap.add_argument("--validate-only", metavar="FILE", help="audit an existing config")
    ap.add_argument("--repair", action="store_true", help="with --validate-only: also write a repaired config")
    a = ap.parse_args()

    if a.validate_only:
        r = run_audit(open(a.validate_only).read(), do_repair=a.repair)
        for x in r["draft_issues"]:
            line = f"line {x['line']}: " if x["line"] and not x["message"].startswith("line") else ""
            print(f"[{x['severity']}] {x['code']}: {line}{x['message']}" + (f"\n        fix: {x['hint']}" if x["hint"] else ""))
        print(f"score {r['history'][0]}/100")
        if a.repair:
            write_outputs(r, a.out)
            for x in r["repairs"]:
                print(f"  repaired (pass {x['pass']}): {x['code']}: {x['action']}")
            print(f"after repair: score {r['score']}/100  errors={r['errors']} warnings={r['warnings']}"
                  f"\nWrote {a.out}/config.txt (repaired), explained.md, verify.md, report.json")
        return
    if not a.request:
        ap.error("give a request or --validate-only")

    try:
        r = run_pipeline(a.request, a.inject_fault,
                         {"device": a.device, "hostname": a.hostname, "base": a.base, "dns": a.dns})
    except ValueError as ex:
        ap.error(str(ex))
    write_outputs(r, a.out)
    print("INTENT   :", json.dumps({k: v for k, v in r["intent"].items() if k != "notes"}))
    print("RETRIEVED:", ", ".join(f"{x['id']}({x['score']})" for x in r["retrieved"]))
    for n in r["intent"]["notes"]:
        print("NOTE     :", n)
    print(f"VALIDATION score history (draft -> repaired): {r['history']}")
    for x in r["repairs"]:
        print(f"  repaired (pass {x['pass']}): {x['code']}: {x['action']}")
    for x in r["issues"]:
        print(f"  [{x['severity']}] {x['code']}: {x['message']}")
    print(f"FINAL    : score {r['score']}/100, errors={r['errors']}, warnings={r['warnings']}")
    print(f"\nWrote {a.out}/config.txt, explained.md, verify.md, report.json\n")
    print(r["config"])


if __name__ == "__main__":
    main()
