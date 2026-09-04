"""Download MITRE D3FEND's NIST SP 800-53 Rev. 5 mapping data."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SOURCE_URL = "https://d3fend.mitre.org/api/mappings/nist.5.json"
DEFAULT_OUTPUT_PATH = Path("data/d3fend_nist_800_53_rev5.json")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    parser.add_argument("--timeout", type=int, default=60)
    return parser.parse_args()


def download_json(source_url: str, timeout: int) -> tuple[dict[str, object], str]:
    request = Request(source_url, headers={"User-Agent": "intelgenz-api/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - known MITRE URL.
            body = response.read()
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Could not download D3FEND NIST mappings: {error}") from error

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError("D3FEND NIST source did not return valid JSON.") from error
    if not isinstance(payload, dict):
        raise RuntimeError("D3FEND NIST source did not return a JSON object.")
    return payload, hashlib.sha256(body).hexdigest()


def write_json(output_path: Path, payload: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    temporary_path.replace(output_path)


def main() -> None:
    arguments = parse_arguments()
    payload, checksum = download_json(arguments.source_url, arguments.timeout)
    write_json(arguments.output, payload)
    bindings = payload.get("results", {})
    count = len(bindings.get("bindings", [])) if isinstance(bindings, dict) else 0
    print(f"Wrote {count} D3FEND-to-NIST mappings to {arguments.output} (SHA-256: {checksum})")


if __name__ == "__main__":
    main()
