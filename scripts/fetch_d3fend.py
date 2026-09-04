"""Download the current MITRE D3FEND ontology JSON-LD graph."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SOURCE_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/d3fend.json"),
        help="Destination JSON-LD file (default: data/d3fend.json).",
    )
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help="D3FEND ontology JSON-LD URL.",
    )
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout in seconds.")
    return parser.parse_args()


def download_json(source_url: str, timeout: int) -> tuple[object, str]:
    """Download and validate a JSON document from the D3FEND source."""
    request = Request(source_url, headers={"User-Agent": "intelgenz-api/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is CLI input.
            body = response.read()
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Could not download MITRE D3FEND data: {error}") from error

    try:
        return json.loads(body), hashlib.sha256(body).hexdigest()
    except json.JSONDecodeError as error:
        raise RuntimeError("MITRE D3FEND source did not return valid JSON.") from error


def write_json(output_path: Path, payload: object) -> None:
    """Write JSON atomically so a failed refresh never corrupts the old file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
    serialized_payload = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    temporary_path.write_text(serialized_payload, encoding="utf-8")
    temporary_path.replace(output_path)


def main() -> None:
    arguments = parse_arguments()
    payload, checksum = download_json(arguments.source_url, arguments.timeout)
    write_json(arguments.output, payload)
    print(f"Wrote D3FEND ontology to {arguments.output} (SHA-256: {checksum})")


if __name__ == "__main__":
    main()
