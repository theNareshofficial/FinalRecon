#!/usr/bin/env python3
import asyncio

from modules.write_log import log_writer

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


async def machine(hostname, session):
    subdomains = []
    error = None

    url = f"http://web.archive.org/cdx/search/cdx?url=*.{hostname}/*&fl=original&collapse=urlkey&limit=50000"
    try:
        async with session.get(url) as resp:
            status = resp.status
            if status == 200:
                raw_data = await resp.text()
                lines = raw_data.split("\n")
                tmp_list = []
                for line in lines:
                    subdomain = (
                        line.replace("http://", "")
                        .replace("https://", "")
                        .split("/")[0]
                        .split(":")[0]
                    )
                    if len(subdomain) > len(hostname):
                        tmp_list.append(subdomain)
                subdomains.extend(tmp_list)
            else:
                error = f"Status : {status}"
                log_writer(f"[wayback_subs] Status = {status}, expected 200")
    except asyncio.TimeoutError:
        error = "Request Timeout"
        log_writer(f"[wayback_subs] Exception = {error}")
    except Exception as exc:
        error = exc
        log_writer(f"[wayback_subs] Exception = {exc}")
    log_writer("[wayback_subs] Completed")
    return "Wayback", subdomains, error
