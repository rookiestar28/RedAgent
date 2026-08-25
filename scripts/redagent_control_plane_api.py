#!/usr/bin/env python3
"""Launch the local-loopback or explicitly private-cluster control-plane API."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import uvicorn  # noqa: E402

from redagent_platform.api.runtime import (  # noqa: E402
    ApiRuntimeError,
    build_runtime_app,
    validate_runtime_bind,
    validate_runtime_tls,
)
from redagent_platform.persistence.database import DatabaseConfigError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback by default; unspecified bind requires --private-cluster-bind.",
    )
    parser.add_argument("--port", default=58000, type=int)
    parser.add_argument(
        "--private-cluster-bind",
        action="store_true",
        help="Allow an unspecified bind only inside the R116 private ClusterIP/NetworkPolicy profile.",
    )
    parser.add_argument("--tls-cert-file", type=Path)
    parser.add_argument("--tls-key-file", type=Path)
    parser.add_argument(
        "--enable-test-issuer",
        action="store_true",
        help="Explicitly enable synthetic local integration headers; never use for shared/production access.",
    )
    parser.add_argument("--log-level", choices=("critical", "error", "warning", "info"), default="info")
    args = parser.parse_args()
    try:
        host, port = validate_runtime_bind(
            args.host,
            args.port,
            private_cluster_bind=args.private_cluster_bind,
        )
        certificate_file, private_key_file = validate_runtime_tls(
            private_cluster_bind=args.private_cluster_bind,
            certificate_file=args.tls_cert_file,
            private_key_file=args.tls_key_file,
        )
        app = build_runtime_app(
            REPO_ROOT,
            test_issuer_enabled=args.enable_test_issuer,
        )
    except (ApiRuntimeError, DatabaseConfigError, OSError) as exc:
        print(f"control_plane_api_error={exc}", file=sys.stderr)
        return 1

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=args.log_level,
        access_log=True,
        server_header=False,
        date_header=False,
        ssl_certfile=certificate_file,
        ssl_keyfile=private_key_file,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
