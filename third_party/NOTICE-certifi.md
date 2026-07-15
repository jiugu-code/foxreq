# certifi dependency notice

foxreq declares `certifi` as a runtime dependency and reads its Mozilla CA bundle when Python callers use `verify=True`.

- Project: certifi
- Source: <https://github.com/certifi/python-certifi>
- Certificate source: Mozilla CA Certificate Program
- License: Mozilla Public License 2.0 (MPL-2.0)

foxreq does not copy the certifi CA bundle into this repository. The bundle is supplied by the installed certifi package and is parsed locally at Session construction time.
