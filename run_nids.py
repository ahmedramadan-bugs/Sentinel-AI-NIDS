"""Start the integrated NIDS service or replay an EVE log once."""

from __future__ import annotations

import argparse
import logging

from nids.dashboard import create_server
from nids.pipeline import NIDSPipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the resilient NIDS pipeline")
    parser.add_argument("--once", action="store_true", help="process the current EVE file then exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    pipeline = NIDSPipeline()
    if args.once:
        pipeline.model.load()
        pipeline.responder.start()
        print(f"Processed {pipeline.process_existing_eve()} EVE events.")
        print(pipeline.status())
        pipeline.stop()
        return 0
    pipeline.start()
    server = create_server(pipeline)
    print(f"NIDS dashboard: http://{pipeline.settings.dashboard_host}:{pipeline.settings.dashboard_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
        pipeline.stop()


if __name__ == "__main__":
    raise SystemExit(main())
