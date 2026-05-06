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
  -- Upstream "host:port" stored as two structured fields so port-conflict
  -- detection and type-safety on the port number are real SQL queries
  -- instead of TEXT parsing.
  target_host TEXT NOT NULL,
  target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port < 65536),
  weight INTEGER NOT NULL DEFAULT 1 CHECK (weight > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Multiple domains pointing at the same upstream is allowed (multi-domain
-- fronting the same backend), so the unique constraint is per (domain,
-- host, port), not just (host, port).
CREATE UNIQUE INDEX IF NOT EXISTS idx_route_upstreams_domain_host_port
  ON route_upstreams (domain, target_host, target_port);
CREATE INDEX IF NOT EXISTS idx_route_upstreams_domain
  ON route_upstreams (domain);
CREATE INDEX IF NOT EXISTS idx_route_upstreams_host_port
  ON route_upstreams (target_host, target_port);

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

-- Free-form tag/group labels for filtering and bulk operations on the
-- Nodes page. Stored as a TEXT[] so we can use Postgres GIN indexes
-- and `&&` (overlap) for multi-tag filters. Operator picks the
-- vocabulary — typically things like "us-edge", "kr", "experiment".
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS groups TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_nodes_groups ON nodes USING GIN (groups);

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

-- Credentials. Industry standard for residential/datacenter proxy
-- providers (Bright Data, Oxylabs, Smartproxy, Decodo, IP2World, …)
-- is ``user:pass@host:port`` — username is essential, not optional,
-- because: (1) ``user:pass`` is the universal auth scheme; (2) many
-- providers encode targeting parameters into the username (e.g.
-- ``customer-leobits-cc-US-city-newyork-session-abc-lifetime-30``).
-- Plaintext storage matches the existing nodes.ssh_password /
-- ssh_keys.passphrase pattern.
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS password TEXT;
-- ``auth_mode`` distinguishes three legitimate states that the UI
-- otherwise can't tell apart from "no creds set":
--   NULL          — auto-detect from username/password (default)
--   'anonymous'   — open public proxy; absence of creds is by design
--   'whitelist'   — provider validates by source IP (no creds in URI)
-- Plain TEXT (no CHECK constraint) so adding a future mode doesn't
-- need a migration; valid values are enforced in application code.
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS auth_mode TEXT;

-- ``kind`` distinguishes how the row should be interpreted by every
-- downstream consumer (geo lookup, quality probe, outbound resolver):
--   'static'   — single endpoint with stable IP. ``ip`` is the actual
--                IP we connect to AND the IP whose location/risk
--                matters. (Default — preserves existing rows.)
--   'gateway'  — provider gateway with a stable HOSTNAME and
--                session-bound exit IPs encoded in the username
--                (Bright Data, Oxylabs, Smartproxy / Decodo, IPRoyal,
--                NetNut, Webshare). ``ip`` holds the gateway hostname
--                (e.g. ``isp.decodo.com``); ``exit_ip`` holds the
--                exit address geo / quality should be computed for.
-- Application code enforces values; schema stays open-coded so adding
-- a future kind (e.g. 'rotating') doesn't require a migration.
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'static';

-- ``exit_ip`` is the upstream-bound exit IP for gateway entries — the
-- address the gateway actually sends traffic from once authenticated.
-- For 'static' kind this is always NULL. For 'gateway' kind it's the
-- subject of geo / quality lookups (the gateway hostname's location
-- doesn't tell us anything about the exit's apparent jurisdiction).
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS exit_ip TEXT;

-- ``gateway_provider`` is a short identifier for the upstream provider
-- ('decodo', 'brightdata', 'oxylabs', 'iproyal', 'smartproxy',
-- 'webshare', 'netnut', or any string) so the UI can render a provider
-- badge and parsing logic can re-use provider-specific session-string
-- conventions. NULL for 'static' kind.
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS gateway_provider TEXT;

-- ``expires_at`` — when the lease / subscription / paid period for
-- this proxy entry runs out. Operator-set; we show a relative-date
-- indicator on the row and color-code "expired", "<7d", "<30d",
-- "ok" so an at-a-glance scan flags upcoming churn. NULL means
-- "no expiry tracked" (free / public proxy / open-ended lease).
ALTER TABLE static_ips ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_static_ips_kind ON static_ips (kind);
CREATE INDEX IF NOT EXISTS idx_static_ips_exit_ip ON static_ips (exit_ip);
CREATE INDEX IF NOT EXISTS idx_static_ips_expires_at ON static_ips (expires_at);

DROP TRIGGER IF EXISTS static_ips_touch_updated_at ON static_ips;
CREATE TRIGGER static_ips_touch_updated_at
BEFORE UPDATE ON static_ips
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS ip_test_results (
  id BIGSERIAL PRIMARY KEY,
  ip_id BIGINT NOT NULL REFERENCES static_ips(id) ON DELETE CASCADE,
  test_kind TEXT NOT NULL DEFAULT 'connectivity'
    CHECK (test_kind IN ('connectivity','probe','manual','loop','test_all','speedtest','quality')),
  success BOOLEAN NOT NULL,
  latency_ms INTEGER,
  error TEXT,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Older deployments still have the narrower CHECK constraint above.
-- Re-create it to include the new kinds. Idempotent.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ip_test_results_test_kind_check'
      AND conrelid = 'ip_test_results'::regclass
  ) THEN
    ALTER TABLE ip_test_results DROP CONSTRAINT ip_test_results_test_kind_check;
  END IF;
  ALTER TABLE ip_test_results
    ADD CONSTRAINT ip_test_results_test_kind_check
    CHECK (test_kind IN ('connectivity','probe','manual','loop','test_all','speedtest','quality'));
END;
$$;

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

-- Structured probe metrics ----------------------------------------------
-- The legacy node_status columns load_avg / memory / disk_usage / os_release
-- store pre-formatted display strings. The columns below hold the same data
-- in a properly typed shape so the UI / downstream tools can compute
-- against them (sort by load, alarm on disk pct, group by OS, etc.) without
-- regex-matching display text. The probe writes both — old text + new
-- structured — every cycle, so both paths stay coherent.
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS load_avg_1m          DOUBLE PRECISION;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS load_avg_5m          DOUBLE PRECISION;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS load_avg_15m         DOUBLE PRECISION;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS memory_total_kb      BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS memory_used_kb       BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS memory_free_kb       BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS memory_available_kb  BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS disk_root_total_kb   BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS disk_root_used_kb    BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS disk_root_avail_kb   BIGINT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS disk_root_used_pct   INTEGER CHECK (disk_root_used_pct IS NULL OR (disk_root_used_pct >= 0 AND disk_root_used_pct <= 100));
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS os_id                TEXT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS os_version_id        TEXT;
ALTER TABLE node_status ADD COLUMN IF NOT EXISTS os_pretty_name       TEXT;

CREATE INDEX IF NOT EXISTS idx_node_status_disk_used_pct
  ON node_status (disk_root_used_pct);
CREATE INDEX IF NOT EXISTS idx_node_status_load_15m
  ON node_status (load_avg_15m);

-- Per-service visual config framework -----------------------------------
-- A service's `.deploy.yaml` declares a ``config_schema`` (a list of
-- {key, label, type, default, help, validate, options, init_only}
-- entries). The admin renders a form from that schema. Per-(service,
-- node) values live in service_node_config; on save we update the row
-- and re-deploy the service with the new env, restarting the container
-- so it picks them up.
ALTER TABLE services
  ADD COLUMN IF NOT EXISTS config_schema JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS service_node_config (
  service_name TEXT NOT NULL REFERENCES services(name) ON DELETE CASCADE ON UPDATE CASCADE,
  node_name    TEXT NOT NULL REFERENCES nodes(name)    ON DELETE CASCADE ON UPDATE CASCADE,
  -- {env_key: value} — matches keys in services.config_schema. Strings,
  -- numbers, booleans pass through; the admin's deploy step renders this
  -- as a .env file on the target node.
  values     JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT,
  PRIMARY KEY (service_name, node_name)
);

CREATE INDEX IF NOT EXISTS idx_service_node_config_service
  ON service_node_config (service_name);

DROP TRIGGER IF EXISTS service_node_config_touch_updated_at ON service_node_config;
CREATE TRIGGER service_node_config_touch_updated_at
BEFORE UPDATE ON service_node_config
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- xout channel: named presets + per-node assignment ---------------------
-- xout (formerly vpsbox) is the multi-inbound proxy service. Operators
-- maintain a small library of named "presets" (each is a list of inbound
-- configs); deploy picks one by id and writes preset.json into the
-- container's /data volume. Per-node assignment lives in
-- xout_node_assignments — single row per node since xout is single-tenant.
CREATE TABLE IF NOT EXISTS xout_presets (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  -- Array of inbound configs. Each entry has at least {tag, protocol,
  -- port}. See vpsbox/scripts/container-entrypoint.sh for the full schema.
  inbounds JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS xout_presets_touch_updated_at ON xout_presets;
CREATE TRIGGER xout_presets_touch_updated_at
BEFORE UPDATE ON xout_presets
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS xout_node_assignments (
  node_name  TEXT PRIMARY KEY REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  preset_id  BIGINT NOT NULL REFERENCES xout_presets(id) ON DELETE RESTRICT,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  applied_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_xout_assignments_preset
  ON xout_node_assignments (preset_id);

-- xout tokens (= xout users) -------------------------------------------
-- One row per logical user. The ``uuid`` is the stable VLESS client id
-- and is reused on every node — that's the value that makes a vless://
-- subscription URL keep working when the operator re-deploys. Mark
-- exactly one row as ``is_default`` (partial unique index enforces it);
-- newly-deployed xout instances seed their first user from that row.
CREATE TABLE IF NOT EXISTS xout_tokens (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  uuid TEXT NOT NULL UNIQUE,
  password TEXT,
  monthly_quota_gb INTEGER NOT NULL DEFAULT 1000
    CHECK (monthly_quota_gb >= 0 AND monthly_quota_gb <= 1000000),
  monthly_reset_day INTEGER NOT NULL DEFAULT 1
    CHECK (monthly_reset_day BETWEEN 1 AND 28),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Note: ``is_default`` and its partial unique index used to live here.
-- Both were dropped in the xout v2 migration further down — the operator
-- now picks the token set explicitly at deploy time, no fallback default.

DROP TRIGGER IF EXISTS xout_tokens_touch_updated_at ON xout_tokens;
CREATE TRIGGER xout_tokens_touch_updated_at
BEFORE UPDATE ON xout_tokens
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- Which tokens are provisioned on which nodes. ``last_seen_at`` is
-- bumped by the sync-traffic path whenever xray's StatsService reports
-- activity for a UUID, so it tracks "this token has been used on this
-- node lately". The cached subscription columns this table once held
-- (base64_subscription, clash_subscription) were dropped as part of
-- the sync-tokens cleanup — admin's subscription handler now reads
-- xout_node_inbounds at request time, exactly like user-service.
CREATE TABLE IF NOT EXISTS xout_node_tokens (
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  token_id  BIGINT NOT NULL REFERENCES xout_tokens(id) ON DELETE CASCADE,
  provisioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at   TIMESTAMPTZ,
  PRIMARY KEY (node_name, token_id)
);

CREATE INDEX IF NOT EXISTS idx_xout_node_tokens_token
  ON xout_node_tokens (token_id);

-- Per-day traffic accumulator. We record one row per (node, token, day);
-- the operator-pulled stats from each xout container's StatsService get
-- snapshotted into here on every "Sync traffic" call. Daily granularity
-- keeps storage tiny and is enough for "this-month total" + "lifetime
-- total" rollups.
CREATE TABLE IF NOT EXISTS xout_traffic_daily (
  node_name TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  token_id  BIGINT NOT NULL REFERENCES xout_tokens(id) ON DELETE CASCADE,
  day DATE NOT NULL,
  uplink_bytes   BIGINT NOT NULL DEFAULT 0,
  downlink_bytes BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (node_name, token_id, day)
);

CREATE INDEX IF NOT EXISTS idx_xout_traffic_daily_day
  ON xout_traffic_daily (day);
CREATE INDEX IF NOT EXISTS idx_xout_traffic_daily_token
  ON xout_traffic_daily (token_id);

-- xout v2 ---------------------------------------------------------------
-- Token value: opaque alphanumeric URL slug (≥24 chars) used as the
-- public identifier for a token in subscription URLs (separate from
-- the internal numeric ``id`` and the VLESS ``uuid``). Auto-generated
-- on row creation; the operator can regenerate but cannot pick the
-- value (length+entropy = security).
ALTER TABLE xout_tokens ADD COLUMN IF NOT EXISTS token_value TEXT;

-- Backfill pre-existing rows. md5() of three jittered sources → 32 hex
-- chars, take 24. Operator can immediately Regenerate after migration
-- to upgrade to the proper python-secrets-token alphabet (a..zA..Z0..9)
-- if they want — this DB-side fallback only exists so the NOT NULL
-- constraint below doesn't blow up on rows we've already shipped.
DO $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN SELECT id FROM xout_tokens WHERE token_value IS NULL LOOP
    UPDATE xout_tokens
       SET token_value = substr(
         md5(random()::text || clock_timestamp()::text || rec.id::text), 1, 24)
     WHERE id = rec.id;
  END LOOP;
END $$;

ALTER TABLE xout_tokens ALTER COLUMN token_value SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_xout_tokens_token_value
  ON xout_tokens (token_value);

-- is_default removed: the operator now picks token set explicitly at
-- deploy time. Empty selection at deploy = error, no fallback.
DROP INDEX IF EXISTS idx_xout_tokens_default_unique;
ALTER TABLE xout_tokens DROP COLUMN IF EXISTS is_default;

-- Preset outbounds: removed. Top-level outbounds were never read by
-- the xout container's entrypoint — it derives outbounds per-inbound
-- from each inbound's `outbound` field. Keeping it as dead data was
-- misleading the operator, so the column is dropped here. The column
-- existed only briefly between two earlier xout schema revisions.
ALTER TABLE xout_presets DROP COLUMN IF EXISTS outbounds;

-- Per-node sync heartbeat. Each xout container writes NOW() into this
-- column at the end of every 30s tick (after reading preset+users from
-- DB and pushing traffic deltas back). The Deployed-nodes UI reads it
-- to show "last synced N seconds ago" — staleness > ~2 min means the
-- container is down or the DB DSN is misconfigured.
ALTER TABLE xout_node_assignments
  ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ;

-- sync-tokens cleanup. The SSH-based reverse-pull path has been
-- removed: admin's subscription handler now reads resolved Reality keys
-- from xout_node_inbounds (which the container upserts on first boot),
-- exactly like user-service's /sub/<token> already does. The two cached
-- subscription strings on xout_node_tokens are no longer written or
-- read by anything; drop them.
ALTER TABLE xout_node_tokens DROP COLUMN IF EXISTS base64_subscription;
ALTER TABLE xout_node_tokens DROP COLUMN IF EXISTS clash_subscription;

-- Init defaults ----------------------------------------------------------
-- The Initialize-a-node flow needs two pieces of credential material:
--   1. an SSH private key it can drop into ~/.ssh on the new VPS so it can
--      git-clone private repos (deploy keys);
--   2. an AI API key + base URL for the Codex CLI install step.
--
-- Both default to the row marked ``is_init_default``; the per-node
-- ``init_git_private_key`` / ``init_codex_api_key`` fields override
-- the default when the operator wants this node to use a specific key.

ALTER TABLE ssh_keys
  ADD COLUMN IF NOT EXISTS is_init_default BOOLEAN NOT NULL DEFAULT FALSE;

-- At most one row at a time may carry the flag. The partial unique index
-- enforces this — toggling on a different row first clears the previous
-- one inside set_ssh_key_init_default().
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_keys_init_default_unique
  ON ssh_keys ((1)) WHERE is_init_default;

CREATE TABLE IF NOT EXISTS ai_api_keys (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL DEFAULT 'https://api.develop.cc/v1',
  api_key TEXT NOT NULL,
  description TEXT,
  is_init_default BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_api_keys_init_default_unique
  ON ai_api_keys ((1)) WHERE is_init_default;

DROP TRIGGER IF EXISTS ai_api_keys_touch_updated_at ON ai_api_keys;
CREATE TRIGGER ai_api_keys_touch_updated_at
BEFORE UPDATE ON ai_api_keys
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

-- New Service flow extensions -------------------------------------------
-- The "New Service" admin form generates a brand-new service repo from a
-- template, registers it here, and creates a route for it. These columns
-- carry the metadata that's specific to that flow:
--   assigned_port     — host port the service binds to on its node; unique
--                       across all services so no two compete for the same
--                       port on the deploy node.
--   local_repo_dir    — absolute path on the operator's machine where the
--                       template was rendered. Surfaced in the UI as
--                       "Open in Finder" so devs jump straight to the code.
--   default_node_name — node the service was first deployed to. Routes
--                       layer can later add more upstreams for HA, but
--                       this records the original.
--   status            — 'active' (deployable) | 'draft' (no repo URL yet,
--                       no deploys allowed) | 'retired' (hidden from UI,
--                       kept for history).
--   product_yaml      — raw .product.yaml content cached at create time so
--                       the products catalog can serve it without cloning
--                       the repo. Refreshed on each deploy.
--   product_enabled   — whether this service appears in the public
--                       products catalog. Defaults to false; operator
--                       flips on once the service is ready to ship.

ALTER TABLE services ADD COLUMN IF NOT EXISTS assigned_port INTEGER
  CHECK (assigned_port IS NULL OR (assigned_port > 0 AND assigned_port < 65536));
ALTER TABLE services ADD COLUMN IF NOT EXISTS local_repo_dir TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS default_node_name TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
  CHECK (status IN ('active','draft','retired'));
ALTER TABLE services ADD COLUMN IF NOT EXISTS product_yaml TEXT;
ALTER TABLE services ADD COLUMN IF NOT EXISTS product_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_services_assigned_port
  ON services (assigned_port) WHERE assigned_port IS NOT NULL;

-- default_node_name → nodes(name). ON DELETE SET NULL so retiring a node
-- doesn't cascade-delete every service that lived on it; ON UPDATE CASCADE
-- so renaming a node still works.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'services_default_node_name_fkey'
      AND conrelid = 'services'::regclass
  ) THEN
    ALTER TABLE services
    ADD CONSTRAINT services_default_node_name_fkey
    FOREIGN KEY (default_node_name) REFERENCES nodes(name)
    ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END;
$$;

-- Routes ↔ services link. When a route is created as part of a service
-- (the New Service flow does this), we record the back-pointer so the
-- admin UI can show the relationship and a "delete service" can offer
-- to clean up its route too.
ALTER TABLE routes ADD COLUMN IF NOT EXISTS service_name TEXT;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'routes_service_name_fkey'
      AND conrelid = 'routes'::regclass
  ) THEN
    ALTER TABLE routes
    ADD CONSTRAINT routes_service_name_fkey
    FOREIGN KEY (service_name) REFERENCES services(name)
    ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_routes_service_name ON routes (service_name);

-- =========================================================================
-- User system (lives in this same schema; ssl-service is read-only on these
-- tables, the user-service deployed at user.develop.cc is the only writer).
-- =========================================================================
--
-- Auth / identity ---------------------------------------------------------
-- We use a single ``auth_users`` row per real person; the email lives on
-- the row directly (a separate user_emails table can be added later if we
-- ever need multi-email-per-user). Passwords live in their own table so a
-- user with only OAuth has no row in auth_passwords. Sessions are
-- DB-backed for v1 (simple revocation, no JWT verifier needed); v2 swaps
-- to JWT + refresh tokens.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Email is stored as plain TEXT; the application lowercases on insert
-- (and a unique index on LOWER(primary_email) enforces that anyway).
-- We avoid citext to skip a non-default extension on managed Postgres.
CREATE TABLE IF NOT EXISTS auth_users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  primary_email   TEXT,
  status          TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','disabled','deleted')),
  locale          TEXT NOT NULL DEFAULT 'zh-CN'
                  CHECK (locale IN ('zh-CN','en-US')),
  display_name    TEXT,
  is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_primary_email
  ON auth_users (LOWER(primary_email)) WHERE primary_email IS NOT NULL;

DROP TRIGGER IF EXISTS auth_users_touch_updated_at ON auth_users;
CREATE TRIGGER auth_users_touch_updated_at
BEFORE UPDATE ON auth_users
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS auth_passwords (
  user_id     UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  argon2_hash TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS auth_passwords_touch_updated_at ON auth_passwords;
CREATE TRIGGER auth_passwords_touch_updated_at
BEFORE UPDATE ON auth_passwords
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS auth_oauth_links (
  id                BIGSERIAL PRIMARY KEY,
  user_id           UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  provider          TEXT NOT NULL CHECK (provider IN ('google','github')),
  provider_user_id  TEXT NOT NULL,
  profile           JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_user_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_oauth_links_user
  ON auth_oauth_links (user_id);

-- Sessions: token is a high-entropy random string; we hash it before
-- storing so a DB leak doesn't immediately give attackers usable
-- session cookies. The plaintext is what goes into the cookie.
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash    TEXT PRIMARY KEY,        -- sha256 of the cookie value
  user_id       UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL,
  last_used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip            TEXT,
  user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
  ON auth_sessions (user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires
  ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS auth_email_verifications (
  token_hash  TEXT PRIMARY KEY,         -- sha256 of the link token
  user_id     UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('verify_email','reset_password')),
  email       TEXT NOT NULL,            -- the email this token authorizes
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_user_kind
  ON auth_email_verifications (user_id, kind, expires_at DESC);

-- Products / billing -----------------------------------------------------
-- ``kind`` distinguishes how the product is consumed:
--   one_time  — a single payment, no expiry
--   recurring — Stripe Subscription (monthly etc.)
--   period    — single payment buys a fixed window (period_days)
--
-- Localized strings (name, description) live as JSONB keyed by BCP-47
-- locale tag (e.g. {"zh-CN": "...", "en-US": "..."}).

CREATE TABLE IF NOT EXISTS products (
  id                 BIGSERIAL PRIMARY KEY,
  code               TEXT NOT NULL UNIQUE,           -- slug, stable
  kind               TEXT NOT NULL
                     CHECK (kind IN ('one_time','recurring','period')),
  price_cents        INTEGER NOT NULL CHECK (price_cents >= 0),
  currency           TEXT NOT NULL DEFAULT 'USD',
  period_days        INTEGER CHECK (period_days IS NULL OR period_days > 0),
  stripe_price_id    TEXT,
  name               JSONB NOT NULL DEFAULT '{}'::jsonb,
  description        JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
  active             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS products_touch_updated_at ON products;
CREATE TRIGGER products_touch_updated_at
BEFORE UPDATE ON products
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS subscriptions (
  id                       BIGSERIAL PRIMARY KEY,
  user_id                  UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  product_id               BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
  status                   TEXT NOT NULL
                           CHECK (status IN ('pending','active','canceled','expired','over_quota')),
  starts_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at               TIMESTAMPTZ,            -- NULL = no expiry
  stripe_subscription_id   TEXT,
  source                   TEXT NOT NULL DEFAULT 'manual'
                           CHECK (source IN ('manual','stripe','grant')),
  metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_status
  ON subscriptions (user_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_product
  ON subscriptions (product_id);

DROP TRIGGER IF EXISTS subscriptions_touch_updated_at ON subscriptions;
CREATE TRIGGER subscriptions_touch_updated_at
BEFORE UPDATE ON subscriptions
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- Usage / quotas ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS usage_events (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  product_id  BIGINT REFERENCES products(id) ON DELETE SET NULL,
  event       TEXT NOT NULL,
  qty         DOUBLE PRECISION NOT NULL DEFAULT 1,
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source      TEXT,                                    -- service name that reported
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_usage_events_user_ts
  ON usage_events (user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_product_ts
  ON usage_events (product_id, ts DESC);

CREATE TABLE IF NOT EXISTS usage_quotas (
  user_id                 UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  product_id              BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  limit_qty               DOUBLE PRECISION NOT NULL,
  reset_kind              TEXT NOT NULL DEFAULT 'never'
                          CHECK (reset_kind IN ('never','monthly_first','monthly_anchor')),
  reset_anchor_day        INTEGER CHECK (reset_anchor_day BETWEEN 1 AND 28),
  current_period_start    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  current_period_consumed DOUBLE PRECISION NOT NULL DEFAULT 0,
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, product_id)
);

DROP TRIGGER IF EXISTS usage_quotas_touch_updated_at ON usage_quotas;
CREATE TRIGGER usage_quotas_touch_updated_at
BEFORE UPDATE ON usage_quotas
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- Payments (Stripe drops payloads here via webhook, indexed for idempotency)

CREATE TABLE IF NOT EXISTS payments (
  id                          BIGSERIAL PRIMARY KEY,
  user_id                     UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  product_id                  BIGINT REFERENCES products(id) ON DELETE SET NULL,
  amount_cents                INTEGER NOT NULL,
  currency                    TEXT NOT NULL DEFAULT 'USD',
  status                      TEXT NOT NULL,           -- stripe payment status
  stripe_payment_intent_id    TEXT UNIQUE,
  stripe_event_id             TEXT UNIQUE,             -- webhook idempotency
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata                    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_payments_user
  ON payments (user_id, created_at DESC);

-- xout user-system migration tables ---------------------------------------
-- New tables, additive — leave the legacy xout_tokens / xout_node_tokens
-- alone for now. The cut-over (P2) drops them once xout is rebuilt to
-- consume auth_users.

CREATE TABLE IF NOT EXISTS xout_products (
  product_id        BIGINT PRIMARY KEY REFERENCES products(id) ON DELETE CASCADE,
  inbound_selector  JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- e.g. {"node_groups": ["us"], "tags": ["vless-tcp"]}
  -- or   {"explicit": [["us01","vless-tcp"], ["us02","vless-tcp"]]}
  metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS xout_products_touch_updated_at ON xout_products;
CREATE TRIGGER xout_products_touch_updated_at
BEFORE UPDATE ON xout_products
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS xout_node_users (
  node_name        TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE ON UPDATE CASCADE,
  user_id          UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  vless_uuid       UUID NOT NULL,                      -- = auth_users.id
  provisioned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at     TIMESTAMPTZ,
  PRIMARY KEY (node_name, user_id)
);
CREATE INDEX IF NOT EXISTS idx_xout_node_users_user
  ON xout_node_users (user_id);

-- Sequence re-sync ------------------------------------------------------
-- After cross-database sync (online→one or primary→one), BIGSERIAL columns
-- can have rows with explicit id values that outrun the local sequence's
-- nextval. The next plain INSERT then trips on a duplicate-key violation.
-- Bump every PK sequence to ``MAX(id) + 1`` so subsequent inserts land
-- after existing rows. Idempotent + cheap; safe to re-run.
DO $$
DECLARE
  rec RECORD;
  max_id BIGINT;
BEGIN
  FOR rec IN
    SELECT
      pg_class_seq.relname AS seq_name,
      pg_class_tab.relname AS table_name,
      pg_attribute.attname AS column_name
    FROM pg_class pg_class_seq
    JOIN pg_depend ON pg_depend.objid = pg_class_seq.oid
    JOIN pg_class pg_class_tab ON pg_class_tab.oid = pg_depend.refobjid
    JOIN pg_attribute ON pg_attribute.attrelid = pg_class_tab.oid
                     AND pg_attribute.attnum = pg_depend.refobjsubid
    JOIN pg_namespace ON pg_namespace.oid = pg_class_seq.relnamespace
    WHERE pg_class_seq.relkind = 'S'
      AND pg_namespace.nspname = current_schema()
  LOOP
    EXECUTE format('SELECT COALESCE(MAX(%I), 0) FROM %I', rec.column_name, rec.table_name)
      INTO max_id;
    -- setval's first argument is regclass; rec.seq_name is type ``name``,
    -- which doesn't auto-cast — go through text first.
    PERFORM setval(rec.seq_name::text::regclass, GREATEST(max_id, 1), max_id > 0);
  END LOOP;
END;
$$;
