"""Generated runtime lock data shipped inside the foxreq wheel.

Do not edit this module by hand. ``scripts/runtime/lock_firefox_release.py``
regenerates it from the reviewed JSON lock files in ``third_party``.
"""

RUNTIME_LOCKS = {
    ("firefox_152", "windows-x86_64"): {
        "schema_version": 1,
        "platform": "windows-x86_64",
        "source_id": "firefox-windows-x86_64-en-us",
        "source_sha256": (
            "3d4fcc5370bb183c9535d64b98d946c2dacf664a394ebcc02844e361d58d59b4"
        ),
        "source_size": 88379520,
        "firefox_version": "152.0.6",
        "firefox_build_id": "20260713164047",
        "nss_version": "3.124",
        "nspr_version": "4.39",
        "files": [
            {
                "filename": "freebl3.dll",
                "size": 1238144,
                "sha256": (
                    "cdfa18b8b81e2b31298858af6d99398ef7ecfb9a9f492bace8e4a668de180878"
                ),
            },
            {
                "filename": "mozglue.dll",
                "size": 709248,
                "sha256": (
                    "d939f19253ab3057a07153bc6c5adcac2d88dc22f35d54fe2ab62c237ffeab39"
                ),
            },
            {
                "filename": "nss3.dll",
                "size": 2973824,
                "sha256": (
                    "eebe84eef0e5f74581c00a9f077df2f4e29ff385b25e3789f641c9d7ff84f190"
                ),
            },
            {
                "filename": "softokn3.dll",
                "size": 353920,
                "sha256": (
                    "9304d1f5e40c3524a13cddc472592ebda6038316c6a0175963a91bd7b430b308"
                ),
            },
        ],
    }
}
