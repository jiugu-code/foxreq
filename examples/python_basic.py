"""在授权目标上演示 foxreq 顶层 Python API。"""

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


def _validate_target(url: str, allow_authorized_target: bool) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("target must be an absolute HTTPS URL without user information")
    if not _is_loopback(parsed.hostname) and not allow_authorized_target:
        raise ValueError(
            "explicit authorization flag is required for non-loopback targets"
        )


def _print_response(response: foxreq.Response) -> None:
    print("status_code={}".format(response.status_code))
    print("http_version={}".format(response.http_version))
    print("body_length={}".format(len(response.content)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="已授权的 HTTPS 请求 URL")
    parser.add_argument("--runtime", required=True, type=Path, help="Firefox NSS 运行时目录")
    parser.add_argument("--ca-pem", required=True, type=Path, help="测试 CA 的 PEM 文件")
    parser.add_argument(
        "--allow-authorized-target",
        action="store_true",
        help="确认非回环目标处于明确授权范围内",
    )
    args = parser.parse_args(argv)

    try:
        _validate_target(args.url, args.allow_authorized_target)
        headers = (("X-Order", "first"), ("X-Order", "second"))
        _print_response(
            foxreq.get(
                args.url,
                headers=headers,
                runtime_dir=args.runtime,
                verify=args.ca_pem,
            )
        )
        _print_response(
            foxreq.post(
                args.url,
                headers=headers,
                json={"ok": True},
                runtime_dir=args.runtime,
                verify=args.ca_pem,
            )
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (foxreq.FoxreqError, OSError):
        print("foxreq request failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
