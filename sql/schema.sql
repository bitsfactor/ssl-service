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

-- Static IPs ----------------------------------------------------------
-- Independent registry of static IP addresses the operator wants to
-- track. Each row is a single (ip, port, protocol) triple plus
-- country/provider attribution and an optional free-form static
-- description (used to store the result of one-off info probes such as
-- streaming-unlock checks). Connectivity testing and full-info probes
-- are recorded as ip_test_results rows.

CREATE TABLE IF NOT EXISTS static_ips (
  id BIGSERIAL PRIMARY KEY,
  ip TEXT NOT NULL,
  port INTEGER CHECK (port IS NULL OR (port > 0 AND port < 65536)),
  protocol TEXT NOT NULL DEFAULT 'tcp',
  country TEXT,
  provider TEXT,
  label TEXT,
  notes TEXT,
  static_info JSONB NOT NULL DEFAULT '{}'::jsonb,
  loop_test_seconds INTEGER,
  last_test_at TIMESTAMPTZ,
  last_test_success BOOLEAN,
  last_test_latency_ms INTEGER,
  last_test_error TEXT,
  last_probe_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_static_ips_ip_port_proto
  ON static_ips (ip, COALESCE(port, 0), protocol);
CREATE INDEX IF NOT EXISTS idx_static_ips_country ON static_ips (country);
CREATE INDEX IF NOT EXISTS idx_static_ips_provider ON static_ips (provider);

DROP TRIGGER IF EXISTS static_ips_touch_updated_at ON static_ips;
CREATE TRIGGER static_ips_touch_updated_at
BEFORE UPDATE ON static_ips
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS ip_test_results (
  id BIGSERIAL PRIMARY KEY,
  ip_id BIGINT NOT NULL REFERENCES static_ips(id) ON DELETE CASCADE,
  test_kind TEXT NOT NULL DEFAULT 'connectivity'
    CHECK (test_kind IN ('connectivity','probe','manual','loop','test_all')),
  success BOOLEAN NOT NULL,
  latency_ms INTEGER,
  error TEXT,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_test_results_ip_created
  ON ip_test_results (ip_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_test_results_created
  ON ip_test_results (created_at DESC);

-- System configuration ------------------------------------------------
-- Generic key/value store for runtime-tunable settings such as the
-- AI-parser endpoint, model, and API key. The admin UI reads/writes
-- this table directly. Values are intentionally stored in plain text
-- per the operator's instruction; treat the schema as low-trust.

CREATE TABLE IF NOT EXISTS system_config (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS system_config_touch_updated_at ON system_config;
CREATE TRIGGER system_config_touch_updated_at
BEFORE UPDATE ON system_config
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- SSH key registry --------------------------------------------------
-- Centralized lifecycle management for the SSH key material the
-- operator uses to authenticate to managed nodes. Both generated and
-- imported keys live here. We store the full private + public key
-- text in plain text per the operator's deliberate decision (the
-- existing `nodes` table already does this for inline keys); the
-- `passphrase` column is optional and likewise plain text.
--
-- Linkage to nodes is by content (nodes.ssh_private_key holds the
-- same PEM body) — we expose "used by N nodes" to the UI by matching
-- text. This avoids an FK migration of the existing nodes table.

CREATE TABLE IF NOT EXISTS ssh_keys (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  key_type TEXT NOT NULL CHECK (key_type IN ('rsa','ed25519','ecdsa','dsa')),
  bits INTEGER,
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  comment TEXT,
  passphrase TEXT,
  source TEXT NOT NULL CHECK (source IN ('generated','imported')) DEFAULT 'generated',
  tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ssh_keys_fingerprint ON ssh_keys (fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_type ON ssh_keys (key_type);

DROP TRIGGER IF EXISTS ssh_keys_touch_updated_at ON ssh_keys;
CREATE TRIGGER ssh_keys_touch_updated_at
BEFORE UPDATE ON ssh_keys
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- Expand nodes.auth_method to allow 'auto' (try key then password). The
-- existing CHECK constraint only accepts 'password' or 'key'; lift it
-- and re-create with the wider set. Both ssh_password and ssh_private_key
-- can now be populated simultaneously regardless of auth_method — the
-- column tells the SSH driver which to attempt first / use, but the
-- inactive credential is preserved on disk so VPS-reinit recovery just
-- means flipping auth_method, not re-typing.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'nodes_auth_method_check'
      AND conrelid = 'nodes'::regclass
  ) THEN
    ALTER TABLE nodes DROP CONSTRAINT nodes_auth_method_check;
  END IF;
END;
$$;

ALTER TABLE nodes
  ADD CONSTRAINT nodes_auth_method_check
  CHECK (auth_method IN ('password', 'key', 'auto'));

-- Many-to-many between nodes and centrally-managed SSH keys ----------
-- A node can have any number of registered keys linked. When the
-- platform connects, it tries every linked key (in priority order)
-- before falling back to password (if auth_method='auto').
--
-- The legacy ``nodes.ssh_private_key`` column stays for backward
-- compatibility — connection logic tries it first as an extra slot.
-- The Edit UI moves the primary input to this junction; inline paste
-- becomes a power-user disclosure.

CREATE TABLE IF NOT EXISTS node_ssh_keys (
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  ssh_key_id BIGINT NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL DEFAULT 100,
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (node_name, ssh_key_id)
);

CREATE INDEX IF NOT EXISTS idx_node_ssh_keys_node
  ON node_ssh_keys (node_name, priority);
CREATE INDEX IF NOT EXISTS idx_node_ssh_keys_key
  ON node_ssh_keys (ssh_key_id);

-- Opportunistic backfill — link existing inline-keyed nodes by exact
-- text match. Idempotent; safe to re-run.
INSERT INTO node_ssh_keys (node_name, ssh_key_id, priority)
SELECT n.name, k.id, 50
FROM nodes n
JOIN ssh_keys k ON k.private_key = n.ssh_private_key
WHERE n.ssh_private_key IS NOT NULL
  AND n.ssh_private_key <> ''
ON CONFLICT (node_name, ssh_key_id) DO NOTHING;

-- Service deployment manifest support ---------------------------------
-- Extends the existing `services` table with the manifest fields the
-- platform reads from each repo's `.deploy.yaml`. Older rows continue
-- to work — these columns just default to empty values.

ALTER TABLE services ADD COLUMN IF NOT EXISTS required_env TEXT[]    NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE services ADD COLUMN IF NOT EXISTS healthcheck  JSONB    NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE services ADD COLUMN IF NOT EXISTS depends_on   TEXT[]   NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE services ADD COLUMN IF NOT EXISTS deploy_yaml  TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS deploy_yaml_fetched_at TIMESTAMPTZ;
ALTER TABLE services ADD COLUMN IF NOT EXISTS exposed_ports INTEGER[] NOT NULL DEFAULT ARRAY[]::INTEGER[];

-- Per-(service, node) deployment history. Each row is one attempt —
-- success or failure — so the operator can see what's running where
-- and roll back if needed.

CREATE TABLE IF NOT EXISTS service_deployments (
  id BIGSERIAL PRIMARY KEY,
  service_name TEXT NOT NULL REFERENCES services(name) ON DELETE CASCADE ON UPDATE CASCADE,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  revision TEXT,                        -- git SHA / tag / branch that was deployed
  status TEXT NOT NULL CHECK (status IN ('pending','running','success','failed','rolled_back')),
  healthcheck_passed BOOLEAN,           -- NULL if no healthcheck configured
  healthcheck_detail TEXT,              -- last response / error
  env_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,   -- effective env at deploy time
  log_text TEXT NOT NULL DEFAULT '',     -- combined stdout/stderr from setup script
  exit_code INTEGER,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  triggered_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_service_deployments_service
  ON service_deployments (service_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_deployments_node
  ON service_deployments (node_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_deployments_status
  ON service_deployments (status);

-- Track which (service, node) currently has which revision running.
-- This is a fast lookup table, kept in sync by application code.
CREATE TABLE IF NOT EXISTS service_node_state (
  service_name TEXT NOT NULL REFERENCES services(name) ON DELETE CASCADE ON UPDATE CASCADE,
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  revision TEXT,
  status TEXT,                          -- mirrors the latest service_deployments row
  last_deployment_id BIGINT REFERENCES service_deployments(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (service_name, node_name)
);

DROP TRIGGER IF EXISTS service_node_state_touch_updated_at ON service_node_state;
CREATE TRIGGER service_node_state_touch_updated_at
BEFORE UPDATE ON service_node_state
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- Liveness columns — populated by `reconcile_node_services()` after each
-- node probe. They reflect *current container state*, not deploy history.
-- The pre-existing `status` column keeps deploy-history semantics
-- (deployed | failed | rolling_back).
ALTER TABLE service_node_state ADD COLUMN IF NOT EXISTS container_state      TEXT;
ALTER TABLE service_node_state ADD COLUMN IF NOT EXISTS container_image      TEXT;
ALTER TABLE service_node_state ADD COLUMN IF NOT EXISTS container_started_at TIMESTAMPTZ;
ALTER TABLE service_node_state ADD COLUMN IF NOT EXISTS healthcheck_ok       BOOLEAN;
ALTER TABLE service_node_state ADD COLUMN IF NOT EXISTS last_observed_at     TIMESTAMPTZ;
