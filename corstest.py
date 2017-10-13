#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# python standard library
import re, sys, ssl, signal, urllib.request, urllib.error, urllib.parse, urllib.parse, argparse, multiprocessing, json, os
from itertools import product


# -------------------------------------------------------------------------------------------------


def usage():

    parser = argparse.ArgumentParser(description="Simple CORS misconfigurations checker")
    parser.add_argument("infile", help="File with domain or URL list")
    parser.add_argument("-c", metavar="name=value", help="Send cookie with all requests")
    parser.add_argument("-p", metavar="processes", help="multiprocessing (default: 32)")
    parser.add_argument("-s", help="always force ssl/tls requests", action="store_true")
    parser.add_argument("-q", help="quiet, allow-credentials only", action="store_true")
    parser.add_argument("-v", help="produce a more verbose output", action="store_true")
    parser.add_argument("-j", help="dump output to a JSON object", action="store_true")
    return parser.parse_args()

# -------------------------------------------------------------------------------------------------


def main():

    global args; args = usage()
    # platform agnostic support, windows does not support os.fork()
    multiprocessing.set_start_method('spawn')

    try:
        urls = [line.rstrip() for line in open(args.infile)]
        zipargs = [args] * len(urls)
        payload = zip(urls,zipargs)
        procs = min(abs(int(args.p or 32)), len(urls)) or 1
    except (IOError, ValueError) as e: print (e); return
    # check domains/urls in parallel but clean exit on ctrl-c
    sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

    signal.signal(signal.SIGINT, sigint_handler)
    try:
        result_array = []
        with multiprocessing.Pool(processes=procs) as pool:
            pool.starmap_async(check, payload).get()

    except KeyboardInterrupt: pass


# -------------------------------------------------------------------------------------------------


# check for vulns/misconfigurations
def check(url,args):
    if re.findall("^https://", url): args.s = True     # set protocol
    url = re.sub("^https?://", "", url)                # url w/o proto
    host = urllib.parse.urlparse("//" + url).hostname or ""  # set hostname
    acao = cors(args, url, url, False, True)                 # perform request
    if acao:
        if args.q and (acao == "no_acac" or "*" == acao): return
        if acao == "*": info(url, "* (without credentials)")
        elif acao in ["//", "://"]: alert(url, "Any origin allowed") # firefox/chrome/safari/opera only
        elif re.findall("\s|,|\|", acao): invalid(url, "Multiple values in Access-Control-Allow-Origin")
        elif re.findall("\*.", acao): invalid(url, 'Wrong use of wildcard, only single "*" is valid')
        elif re.findall("fiddle.jshell.net|s.codepen.io", acao): alert(url, "Developer backdoor")
        elif "evil.org" in cors(args, url, "evil.org"): alert(url, "Origin reflection")
        elif "null" == cors(args, url, "null").lower(): alert(url, "Null misconfiguration")
        elif host+".tk" in cors(args, url, host+".tk"): alert(url, "Post-domain wildcard")
        elif "not"+host in cors(args, url, "not"+url):
            alert(url, "Pre-domain wildcard") if sld(host) else warning(url, "Pre-subdomain wildcard")
        elif "sub."+host in cors(args, url, "sub."+url): warning(url, "Arbitrary subdomains allowed")
        elif cors(args, url, url, True).startswith("http://"): warning(url, "Non-ssl site allowed")
        else: info(url, acao)
    elif acao != None and not args.q: notvuln(url, "Access-Control-Allow-Origin header not present")
    # TBD: maybe use CORS preflight options request instead to check if cors protocol is understood
    sys.stdout.flush()


# -------------------------------------------------------------------------------------------------


# perform request and fetch response header
def cors(args, url, origin, ssltest=False, firstrun=False):
    url = ("http://" if not (ssltest or args.s) else "https://") + url
    if origin != "null": origin = ("http://" if (ssltest or not args.s) else "https://") + origin
    try:
        request = urllib.request.Request(url)
        request.add_header('Origin', origin)
        request.add_header('Cookie', args.c or "")
        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64)')
        if not "_create_unverified_context" in dir(ssl): response = urllib.request.urlopen(request, timeout=10)
        else: response = urllib.request.urlopen(request, timeout=10, context=ssl._create_unverified_context())
        acao = response.info().get('Access-Control-Allow-Origin')
        acac = str(response.info().get('Access-Control-Allow-Credentials')).lower() == "true"
        vary = "Origin" in str(response.info().get('Vary'))
        if args.v: print("%s\n%-10s%s\n%-10s%s\n%-10s%s\n%-10s%s" % ("-" * 72, "Resource:",
            response.geturl(), "Origin:", origin, "ACAO:", acao or "-", "ACAC:", acac or "-"))
        if firstrun:
            if args.q and not acac: acao = "no_acac"
            if acac and acao != '*' and not args.q: alert(url, "Access-Control-Allow-Credentials present")
            if vary and not args.q: warning(url, "Access-Control-Allow-Origin dynamically generated")
            if ssltest and response.info().get('Strict-Transport-Security'): acao = ""
        return (acao or "") if acac else ""
    except Exception as e:
        if not args.q: error(url, str(e) or str(e).splitlines()[-1])
        if not firstrun: return ""


# -------------------------------------------------------------------------------------------------


# check if given hostname is a second-level domain
def sld(host):

    try:
        with open('tldlist.dat') as f: tlds = [line.strip() for line in f if line[0] not in "/\n"][::-1]
    except IOError as e: return True
    for tld in tlds:
        if host.endswith('.' + tld): host = host[:-len(tld)]
    if host.count('.') == 1: return True


# -------------------------------------------------------------------------------------------------


def log_to_file(filepath,text):
    with open(filepath,'a') as file:
        file.writelines(text)
        file.writelines("\n")


# -------------------------------------------------------------------------------------------------


def error(url, msg):  result = "[ERROR] " + url + " : " + msg;print(result)
def alert(url, msg): result = "[ALERT] " + url + " : " + msg;print(result)
def invalid(url, msg): result = "[INVALID] " + url + " : " + msg;print(result)
def warning(url, msg): result = "[WARNING] " + url + " : " + msg;print(result)
def notvuln(url, msg): result = "[NOTVULNERABLE] " + url + " : " + msg;print(result)
def info(url, msg): result = "[INFO] " + url + " : Access-Control-Allow-Origin = " + msg;print(result)


# -------------------------------------------------------------------------------------------------


if __name__ == '__main__':
    main()
