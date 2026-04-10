#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import psycopg
import yaml


def load_dsn(config_path: Path) -> str:
  data = yaml.safe_load(config_path.read_text()) or {}
  return str(data["postgres"]["dsn"])


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description="Recover missing route rows from existing certificate records."
  )
  parser.add_argument(
    "--config",
    default="/etc/ssl-proxy/config.yaml",
    help="path to ssl-proxy YAML config",
  )
  parser.add_argument(
    "--enable",
    action="store_true",
    help="recover routes as enabled instead of disabled",
  )
  parser.add_argument(
    "--default-target",
    default=None,
    help="optional upstream_target to assign to recovered routes",
  )
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  dsn = load_dsn(Path(args.config))

  with psycopg.connect(dsn, sslmode="require") as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO routes (
          domain,
          upstream_target,
          enabled,
          updated_at
        )
        SELECT
          c.domain,
          %s,
          %s,
          NOW()
        FROM certificates c
        WHERE NOT EXISTS (
          SELECT 1
          FROM routes r
          WHERE r.domain = c.domain
        )
        ORDER BY c.domain ASC
        RETURNING domain
        """,
        (args.default_target, args.enable),
      )
      recovered = [row[0] for row in cur.fetchall()]
    conn.commit()

  if recovered:
    print("recovered routes:")
    for domain in recovered:
      print(domain)
  else:
    print("no routes needed recovery")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
