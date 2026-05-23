#!/usr/bin/env python3

import re
from collections import defaultdict
from operator import itemgetter
from urllib.parse import parse_qs, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.export import export
from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
HEADER = "\033[1;35m"  # bold magenta

JUICY_EXT = {
    "js",
    "json",
    "xml",
    "yaml",
    "yml",
    "env",
    "config",
    "conf",
    "bak",
    "backup",
    "old",
    "sql",
    "db",
    "log",
    "txt",
    "zip",
    "tar",
    "gz",
    "key",
    "pem",
    "php",
    "asp",
    "aspx",
    "jsp",
}

JUICY_PATHS = re.compile(
    r"/(admin|api|v\d+|graphql|internal|debug|swagger|openapi|"
    r"metrics|actuator|\.git|\.env|backup|upload|export|"
    r"config|dashboard|console)(/|$|\?)",
    re.IGNORECASE,
)

JUICY_PARAMS = re.compile(
    r"[?&](url|redirect|next|return|goto|dest|file|path|"
    r"id|uid|user_id|account|order|invoice|"  # IDOR
    r"cmd|exec|command|query|search|"  # injection
    r"token|key|secret|api_key|access_token|auth|"  # secrets
    r"src|source|host|domain|endpoint|"  # SSRF
    r"callback|jsonp|"  # JSONP/open redirect
    r"template|include|page|view|load|"  # LFI/path traversal
    r"debug|test|admin)=",  # logic flaws
    re.IGNORECASE,
)


def analyze(url_list):
    intel = {
        "all_urls": [],
        "js_files": [],
        "api_endpoints": [],
        "juicy_paths": [],
        "juicy_params": [],
        "juicy_ext": defaultdict(list),
        "param_summary": defaultdict(int),
    }

    for url in url_list:
        if not url or not url.startswith("http"):
            continue

        intel["all_urls"].append(url)

        try:
            parsed = urlparse(url)
        except Exception:
            continue

        path = parsed.path.lower()
        ext = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""

        if ext in JUICY_EXT:
            intel["juicy_ext"][ext].append(url)
        if ext == "js":
            intel["js_files"].append(url)
        if re.search(
            r"/api/|/graphql|/graphiql|/gql|/rest/|/v\d+|/rpc|/endpoint", path
        ):
            intel["api_endpoints"].append(url)
        elif JUICY_PATHS.search(parsed.path):
            intel["juicy_paths"].append(url)
        if parsed.query and JUICY_PARAMS.search("?" + parsed.query):
            intel["juicy_params"].append(url)
            for param in parse_qs(parsed.query):
                intel["param_summary"][param] += 1

    intel["param_summary"] = dict(
        sorted(intel["param_summary"].items(), key=itemgetter(1), reverse=True)
    )
    intel["juicy_ext"] = {k: list(set(v)) for k, v in intel["juicy_ext"].items()}
    return intel


def print_summary(intel):
    print(f" {G}❯{W} Total URLs         : {len(intel['all_urls'])}")
    print(f" {G}❯{W} JS files           : {len(intel['js_files'])}")
    print(f" {G}❯{W} API endpoints      : {len(intel['api_endpoints'])}")
    print(f" {G}❯{W} Interesting paths  : {len(intel['juicy_paths'])}")
    print(f" {G}❯{W} Interesting params : {len(intel['juicy_params'])}")

    if intel["juicy_ext"]:
        exts = ", ".join(
            f"{e}({len(v)})" for e, v in sorted(intel["juicy_ext"].items())
        )
        print(f" {Y}❯{W} Sensitive exts     : {exts}")

    if intel["param_summary"]:
        top = list(intel["param_summary"].items())[:8]
        print(f" {Y}❯{W} Top params         : {', '.join(f'{p}={c}' for p, c in top)}")

    if intel["juicy_ext"]:
        for ext, urls in sorted(intel["juicy_ext"].items()):
            print(f"\n{Y}.{ext} :{W}")
            for url in urls[:3]:
                print(url)

    if intel["api_endpoints"]:
        print(f"\n{Y}API Endpoints :{W}")
        for url in intel["api_endpoints"][:5]:
            print(url)

    if intel["juicy_params"]:
        print(f"\n{Y}Parameters :{W}")
        for url in intel["juicy_params"][:5]:
            print(url)


def timetravel(target, data, output):
    wayback_total = []
    result = {}
    r_data = None
    domain_query = f"{target}/*"

    print(f"\n{HEADER}━━━ Wayback Machine {'━' * 30}{W}\n")

    print(f"{C}[*]{W} Time travelling...")
    wm_url = "http://web.archive.org/cdx/search/cdx"

    payload = {
        "url": domain_query,
        "fl": "original",
        "collapse": "urlkey",
        "limit": 50000,
    }

    try:
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=2, status_forcelist=[500, 502, 503])
        s.mount(
            "http://",
            HTTPAdapter(max_retries=retry),
        )

        rqst = s.get(wm_url, params=payload, timeout=30)
        r_sc = rqst.status_code
        if r_sc == 200:
            r_data = rqst.text
            r_data = set(r_data.split("\n"))
            wayback_total.extend(r_data)

            print(f"\n{C}[*]{W} Analyzing...\n")
            intel = analyze(r_data)
            print_summary(intel)
        else:
            print(f"\n{R}[-]{W} Status : {r_sc}")
            log_writer(f"[wayback] Status = {r_sc}, expected 200")

        if r_data:
            if output != "None":
                flat = []
                flat.append("\n=== JS FILES ===")
                flat.extend(intel["js_files"])
                flat.append("\n=== API ENDPOINTS ===")
                flat.extend(intel["api_endpoints"])
                flat.append("\n=== JUICY PARAMS ===")
                flat.extend(intel["juicy_params"])
                flat.append("\n=== SENSITIVE EXTENSIONS ===")
                for ext, urls in sorted(intel["juicy_ext"].items()):
                    flat.append(f".{ext}:")
                    flat.extend(urls)
                result["links"] = flat
                result.update({"exported": False})
                raw_results = {}
                raw_results.update({"wayback_urls": wayback_total})
                raw_results.update({"exported": False})
                data["module-wayback_urls"] = result
                fname = f"{output['directory']}/wayback_urls.{output['format']}"
                output["file"] = fname
                export(output, data)
                print(f"\n{C}[*]{W} Exported triaged urls at {fname}\n")
                data["module-wayback_urls-raw"] = raw_results
                fname_raw = f"{output['directory']}/wayback_urls_raw.{output['format']}"
                output["file"] = fname_raw
                export(output, data)
                print(f"{C}[*]{W} Exported raw urls at {fname_raw}")
        else:
            print(f"{R}[-]{W} No URLs Found!")
            log_writer("[wayback] No URLs Found!")
    except Exception as exc:
        print(f"\n{R}[-]{W} Exception : {exc}")
        log_writer(f"[wayback] Exception = {exc}")
    log_writer("[wayback] Completed")
