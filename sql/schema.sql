CREATE TABLE IF NOT EXISTS routes (
  domain TEXT PRIMARY KEY,
  upstream_port INTEGER CHECK (upstream_port > 0 AND upstream_port < 65536),
  upstream_target TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE routes
ALTER COLUMN upstream_port DROP NOT NULL;

ALTER TABLE routes
ADD COLUMN IF NOT EXISTS upstream_target TEXT;

UPDATE routes
SET upstream_target = '127.0.0.1:' || upstream_port::text
WHERE upstream_target IS NULL
  AND upstream_port IS NOT NULL;

CREATE TABLE IF NOT EXISTS certificates (
  domain TEXT PRIMARY KEY,
  fullchain_pem TEXT NOT NULL,
  private_key_pem TEXT NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  source TEXT NOT NULL DEFAULT 'manual',
  retry_after TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS dns_zone_tokens (
  zone_name TEXT PRIMARY KEY,
  provider TEXT NOT NULL DEFAULT 'cloudflare',
  zone_id TEXT NOT NULL,
  api_token TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'certificates_domain_fkey'
      AND conrelid = 'certificates'::regclass
  ) THEN
    ALTER TABLE certificates
    ADD CONSTRAINT certificates_domain_fkey
    FOREIGN KEY (domain)
    REFERENCES routes (domain)
    ON DELETE RESTRICT;
  END IF;
END;
$$;

-- Multi-upstream + load-balancing policy ---------------------------------
-- Each route can point to 1..N upstream servers. `routes.upstream_target`
-- stays for backward compatibility and is kept in sync with the "primary"
-- (first) row in route_upstreams.

ALTER TABLE routes
ADD COLUMN IF NOT EXISTS lb_policy TEXT NOT NULL DEFAULT 'random';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'routes_lb_policy_check'
  ) THEN
    ALTER TABLE routes
    ADD CONSTRAINT routes_lb_policy_check
    CHECK (lb_policy IN ('random','round_robin','ip_hash','uri_hash'));
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS route_upstreams (
  id BIGSERIAL PRIMARY KEY,
  domain TEXT NOT NULL REFERENCES routes(domain) ON DELETE CASCADE,
  target TEXT NOT NULL,
  weight INTEGER NOT NULL DEFAULT 1 CHECK (weight > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_route_upstreams_domain_target
  ON route_upstreams (domain, target);
CREATE INDEX IF NOT EXISTS idx_route_upstreams_domain
  ON route_upstreams (domain);

-- Backfill any legacy row that has a non-null upstream_target but no
-- corresponding entry in route_upstreams yet. Safe to re-run.
INSERT INTO route_upstreams (domain, target, weight, updated_at)
SELECT r.domain, r.upstream_target, 1, NOW()
FROM routes r
WHERE r.upstream_target IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM route_upstreams ru WHERE ru.domain = r.domain
  );

CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes (enabled);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_dns_zone_tokens_provider ON dns_zone_tokens (provider);

CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS routes_touch_updated_at ON routes;
CREATE TRIGGER routes_touch_updated_at
BEFORE UPDATE ON routes
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS certificates_touch_updated_at ON certificates;
CREATE TRIGGER certificates_touch_updated_at
BEFORE UPDATE ON certificates
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS dns_zone_tokens_touch_updated_at ON dns_zone_tokens;
CREATE TRIGGER dns_zone_tokens_touch_updated_at
BEFORE UPDATE ON dns_zone_tokens
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS route_upstreams_touch_updated_at ON route_upstreams;
CREATE TRIGGER route_upstreams_touch_updated_at
BEFORE UPDATE ON route_upstreams
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- Node management ---------------------------------------------------------
-- Each node represents a remote machine the operator wants to manage.
-- SSH credentials are stored alongside (password OR private key + optional
-- passphrase). Authentication material is stored as plaintext for the
-- prototype; a future pass should encrypt-at-rest using a key in config.

CREATE TABLE IF NOT EXISTS nodes (
  name TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port > 0 AND ssh_port < 65536),
  ssh_user TEXT NOT NULL DEFAULT 'root',
  auth_method TEXT NOT NULL CHECK (auth_method IN ('password', 'key')),
  ssh_password TEXT,
  ssh_private_key TEXT,
  ssh_key_passphrase TEXT,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  deploy_command TEXT,
  update_command TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS node_status (
  node_name TEXT PRIMARY KEY REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  reachable BOOLEAN NOT NULL DEFAULT FALSE,
  service_installed BOOLEAN,
  service_running BOOLEAN,
  service_mode TEXT,
  service_version TEXT,
  uptime_seconds BIGINT,
  load_avg TEXT,
  memory TEXT,
  disk_usage TEXT,
  os_release TEXT,
  last_probed_at TIMESTAMPTZ,
  last_probe_error TEXT,
  raw_probe JSONB
);

CREATE INDEX IF NOT EXISTS idx_nodes_host ON nodes (host);

-- Initialization defaults stored on each node row. Used as defaults when
-- the operator runs the "Initialize" wizard, and persisted back so the
-- next initialization can pre-fill from prior choices.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_git_private_key TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_git_user_name TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_git_user_email TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_desired_ssh_port INTEGER DEFAULT 60101 CHECK (init_desired_ssh_port IS NULL OR (init_desired_ssh_port > 0 AND init_desired_ssh_port < 65536));
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_install_codex BOOLEAN DEFAULT TRUE;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_codex_base_url TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_codex_api_key TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS init_timezone TEXT DEFAULT 'Asia/Shanghai';

-- One row per init run. The orchestrator appends to log_text as it goes,
-- and the polling endpoint just reads this row.
CREATE TABLE IF NOT EXISTS node_init_runs (
  id BIGSERIAL PRIMARY KEY,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued','running','success','failed','cancelled')),
  current_step TEXT,
  log_text TEXT NOT NULL DEFAULT '',
  exit_code INTEGER,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  config_snapshot JSONB
);
CREATE INDEX IF NOT EXISTS idx_node_init_runs_node ON node_init_runs (node_name, started_at DESC);

-- Service catalog --------------------------------------------------------
-- Each row defines a deployable service: a github repo to pull, a path
-- to its compose file, plus default env values that the deploy step
-- writes into a .env on the target node before running `docker compose
-- up -d --build`.

CREATE TABLE IF NOT EXISTS services (
  name TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description TEXT,
  github_repo_url TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  compose_file TEXT NOT NULL DEFAULT 'docker-compose.yml',
  install_dir_template TEXT NOT NULL DEFAULT '/opt/{name}',
  default_env JSONB NOT NULL DEFAULT '{}'::jsonb,
  pre_deploy_command TEXT,
  post_deploy_command TEXT,
  compose_template TEXT,
  config_files JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- For already-existing tables (idempotent additive migration)
ALTER TABLE services ADD COLUMN IF NOT EXISTS compose_template TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS config_files JSONB NOT NULL DEFAULT '{}'::jsonb;

DROP TRIGGER IF EXISTS services_touch_updated_at ON services;
CREATE TRIGGER services_touch_updated_at
BEFORE UPDATE ON services
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- Backfill ON UPDATE CASCADE on node_* foreign keys for already-existing
-- tables. Safe to re-run; only swaps the constraint when needed.
DO $$
DECLARE
  fk RECORD;
BEGIN
  FOR fk IN
    SELECT conname, conrelid::regclass AS tbl
    FROM pg_constraint
    WHERE confrelid = 'nodes'::regclass
      AND confupdtype <> 'c'  -- 'c' = CASCADE
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.tbl, fk.conname);
    EXECUTE format(
      'ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (node_name) REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE',
      fk.tbl, fk.conname
    );
  END LOOP;
END;
$$;

DROP TRIGGER IF EXISTS nodes_touch_updated_at ON nodes;
CREATE TRIGGER nodes_touch_updated_at
BEFORE UPDATE ON nodes
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();
