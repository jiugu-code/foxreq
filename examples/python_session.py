"""在授权目标上演示 foxreq Session 连接复用。"""

import argparse
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlsplit

import foxreq


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_origin(origin: str, allow_authorized_target: bool) -> str:
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("origin must be an HTTPS origin without credentials, query, or fragment")
    if not _is_loopback(parsed.hostname) and not allow_authorized_target:
        raise ValueError(
            "explicit authorization flag is required for non-loopback targets"
        )
    return origin.rstrip("/")


def _print_response(response: foxreq.Response) -> None:
    print("status_code={}".format(response.status_code))
    print("http_version={}".format(response.http_version))
    print("body_length={}".format(len(response.content)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="已授权的 HTTPS 源站")
    parser.add_argument("--runtime", required=True, type=Path, help="Firefox NSS 运行时目录")
    parser.add_argument("--ca-pem", required=True, type=Path, help="测试 CA 的 PEM 文件")
    parser.add_argument(
        "--allow-authorized-target",
        action="store_true",
        help="确认非回环目标处于明确授权范围内",
    )
    args = parser.parse_args(argv)

    try:
        origin = _validate_origin(args.origin, args.allow_authorized_target)
        with foxreq.Session(runtime_dir=args.runtime, verify=args.ca_pem) as session:
            _print_response(session.get(origin + "/one"))
            _print_response(session.get(origin + "/two"))
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (foxreq.FoxreqError, OSError):
        print("foxreq request failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
