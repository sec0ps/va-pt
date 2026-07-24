"""Manual darkweb search CLI over Tor using configured sources."""

import sys
import json
import argparse
import logging

from config import Config
from torctl import TorController
from fetch import TorFetcher
from sources.ahmia import AhmiaSource


def build_parser():
    parser = argparse.ArgumentParser(description="Manual darkweb search over Tor")
    parser.add_argument("-t", "--term", required=True, action="append",
                        help="search term, may be repeated")
    parser.add_argument("-e", "--engagement", default="default",
                        help="engagement tag used for circuit isolation")
    parser.add_argument("-l", "--limit", type=int, default=50,
                        help="max results per term")
    parser.add_argument("--json", action="store_true", help="emit json output")
    parser.add_argument("--quiet", action="store_true", help="suppress tor bootstrap logs")
    return parser


def run(args):
    config = Config()
    if args.quiet:
        config.tor_verbose = False
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    source = AhmiaSource(config.ahmia_base_url)
    output = []

    with TorController(config) as tor:
        fetcher = TorFetcher(tor, config)
        for term in args.term:
            hits = source.search(term, fetcher, isolation=args.engagement, limit=args.limit)
            output.append({"term": term, "source": source.name,
                           "hits": [h.__dict__ for h in hits]})

    emit(output, args.json)


def emit(output, as_json):
    if as_json:
        print(json.dumps(output, indent=2))
        return
    for block in output:
        print("\n== %s (%s) ==" % (block["term"], block["source"]))
        if not block["hits"]:
            print("  no results")
            continue
        for hit in block["hits"]:
            print("  %s" % hit["title"])
            print("    %s" % hit["url"])
            if hit["snippet"]:
                print("    %s" % hit["snippet"][:200])


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
