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
  -- Nullable since 2026-05-09: services with `local_repo_dir` set
  -- and no GitHub mirror are deployed via local-deploy mode (the
  -- admin tars + ssh-pushes the source dir). The deploy code path
  -- already treats empty github_repo_url as the "use local" trigger;
  -- the column was previously NOT NULL purely by historical accident.
  github_repo_url TEXT,
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
-- Drop NOT NULL on github_repo_url for existing deployments (idempotent).
ALTER TABLE services ALTER COLUMN github_repo_url DROP NOT NULL;

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

-- Preset outbounds: removed. Top-level outbounds were never read by
-- the xout container's entrypoint — it derives outbounds per-inbound
-- from each inbound's `outbound` field.
ALTER TABLE xout_presets DROP COLUMN IF EXISTS outbounds;

-- Per-node sync heartbeat. Each xout container writes NOW() into this
-- column at the end of every 30s tick. Deployed-nodes UI shows
-- "last synced N seconds ago"; staleness > ~2 min ⇒ container down.
ALTER TABLE xout_node_assignments
  ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ;

-- Legacy operator-managed xout_tokens / xout_node_tokens / xout_traffic_daily
-- tables were removed in the user-system unification. The single source
-- of truth for "who can use xout" is now auth_users + subscriptions
-- + xout_products. See the user-system migration block at the bottom
-- of this file for column additions and DROP TABLE statements.

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
-- One row per real person. username + primary_email + a password row in
-- auth_passwords are all required; vless_uuid and subscription_token
-- are auto-generated and never user-visible (operator can't pick them).
-- The migration block at the bottom of this file backfills, hardens
-- NOT NULL, and adds unique indexes for existing DBs that pre-date these
-- columns -- so this CREATE TABLE matches the steady-state shape after
-- migration.
CREATE TABLE IF NOT EXISTS auth_users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username            TEXT,                              -- NOT NULL added in migration
  primary_email       TEXT,                              -- NOT NULL added in migration
  vless_uuid          UUID DEFAULT gen_random_uuid(),    -- NOT NULL added in migration
  subscription_token  TEXT,                              -- NOT NULL added in migration
  status              TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','disabled','deleted')),
  locale              TEXT NOT NULL DEFAULT 'zh-CN'
                      CHECK (locale IN ('zh-CN','en-US')),
  display_name        TEXT,
  is_admin            BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified_at   TIMESTAMPTZ,
  metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Backfill column for DBs that pre-date the email_verified_at addition.
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

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
-- Enforce: at most one (user, product) row in non-terminal status at a
-- time. Without this, two concurrent grants race into duplicate active
-- subs that the operator then has to manually clean up.
-- Pre-fixup: a pre-migration DB may already have duplicate active subs
-- (this happens when the operator double-clicked grant before the
-- index was added). Keep the latest by id and cancel the rest so
-- CREATE INDEX doesn't fail on existing data.
WITH dups AS (
  SELECT id,
         row_number() OVER (PARTITION BY user_id, product_id
                              ORDER BY id DESC) AS rn
    FROM subscriptions
   WHERE status IN ('pending', 'active', 'over_quota')
)
UPDATE subscriptions
   SET status = 'canceled', updated_at = NOW()
 WHERE id IN (SELECT id FROM dups WHERE rn > 1);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_one_active_per_user_product
  ON subscriptions (user_id, product_id)
  WHERE status IN ('pending', 'active', 'over_quota');

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

-- Stripe webhook failures ------------------------------------------------
-- When the webhook handler raises after signature verification (a logic
-- bug, a DB transient, etc.) Stripe sees a 500 and retries silently for
-- ~3 days. We were learning about failures only by ssh-ing into the
-- container to grep stderr — and stderr gets wiped on every redeploy.
-- This table is a persistent audit log: every uncaught exception inside
-- the handler writes one row + the raw exception text + the event id,
-- so a future "user paid but subscription didn't update" report can be
-- diagnosed by a single SQL query.
CREATE TABLE IF NOT EXISTS stripe_webhook_failures (
  id              BIGSERIAL PRIMARY KEY,
  event_id        TEXT,                                  -- Stripe event id; may be NULL if parsing the body failed
  event_type      TEXT,                                  -- e.g. checkout.session.completed
  user_id         UUID REFERENCES auth_users(id) ON DELETE SET NULL,
  product_id      BIGINT REFERENCES products(id) ON DELETE SET NULL,
  error_message   TEXT NOT NULL,                         -- str(exc) — short
  error_traceback TEXT,                                  -- full traceback for debugging
  request_body    TEXT,                                  -- raw incoming body (capped to ~8 KB)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_failures_created
  ON stripe_webhook_failures (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_failures_event_id
  ON stripe_webhook_failures (event_id);

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

-- xout_node_users (legacy per-(node, user) VLESS UUID table) was removed
-- in the user-system unification. The user's VLESS UUID is now a single
-- value on auth_users (see migration block at the bottom of this file).

-- =========================================================================
-- User-system unification migration -- one source of truth for "users"
-- =========================================================================
-- Goals after this migration:
--   1. auth_users carries username + email + password_hash (all required,
--      username and email globally unique). primary_email becomes NOT NULL.
--   2. auth_users carries vless_uuid (one per user, not per (user, node))
--      and subscription_token (one URL per user, not per subscription).
--      Both auto-generated at creation and globally unique.
--   3. Legacy xout_tokens / xout_node_tokens / xout_traffic_daily are
--      gone. xout_node_users is gone.
--   4. subscriptions.subscription_token is gone -- /sub URL is now keyed
--      off auth_users.subscription_token, returning *all* of that user's
--      active xout subs aggregated.
-- Idempotent. Re-running is a no-op once the new state is reached.

-- Helper: random url-safe slug, used for default subscription_token.
-- 18 random bytes ⇒ 24 base64 chars; translate to make url-safe.
-- Schema-qualifies gen_random_bytes because Supabase installs pgcrypto
-- under the ``extensions`` schema, which isn't on the default search_path.
CREATE OR REPLACE FUNCTION _gen_url_safe_token() RETURNS TEXT
LANGUAGE sql VOLATILE AS $$
  SELECT translate(encode(extensions.gen_random_bytes(18), 'base64'), '+/=', '-_')
$$;

-- 1. username (TEXT, NOT NULL, UNIQUE case-insensitive).
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS username TEXT;
-- Backfill from email local-part for any row missing one.
-- Collisions are resolved by appending a numeric suffix.
DO $$
DECLARE
  rec RECORD;
  candidate TEXT;
  attempt INT;
BEGIN
  FOR rec IN SELECT id, primary_email FROM auth_users
              WHERE username IS NULL OR username = '' LOOP
    candidate := lower(regexp_replace(
      split_part(COALESCE(rec.primary_email, ''), '@', 1),
      '[^a-z0-9_.-]', '', 'gi'));
    IF candidate = '' THEN
      candidate := 'user_' || substr(rec.id::text, 1, 8);
    END IF;
    attempt := 0;
    WHILE EXISTS (SELECT 1 FROM auth_users
                  WHERE LOWER(username) = LOWER(
                    candidate || CASE WHEN attempt = 0 THEN ''
                                      ELSE '_' || attempt::text END))
    LOOP
      attempt := attempt + 1;
    END LOOP;
    UPDATE auth_users
       SET username = candidate || CASE WHEN attempt = 0 THEN ''
                                        ELSE '_' || attempt::text END
     WHERE id = rec.id;
  END LOOP;
END $$;
ALTER TABLE auth_users ALTER COLUMN username SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_username
  ON auth_users (LOWER(username));

-- 2. primary_email NOT NULL (already has unique-on-LOWER index).
UPDATE auth_users SET primary_email = LOWER(primary_email)
  WHERE primary_email IS NOT NULL;
-- For rows with NULL email (shouldn't happen in prod but defensive):
UPDATE auth_users SET primary_email = username || '@unknown.local'
  WHERE primary_email IS NULL OR primary_email = '';
ALTER TABLE auth_users ALTER COLUMN primary_email SET NOT NULL;

-- 3. vless_uuid (UUID, NOT NULL, UNIQUE).
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS vless_uuid UUID;
-- For users that already have rows in (now-defunct) xout_node_users with
-- a stable VLESS UUID, preserve that value so existing clients keep
-- working without re-issuing subscription URLs. We only do this lookup
-- when the legacy table still exists (idempotent re-runs).
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
     WHERE table_schema = current_schema()
       AND table_name = 'xout_node_users'
  ) THEN
    EXECUTE $migrate$
      UPDATE auth_users u
         SET vless_uuid = sub.vless_uuid
        FROM (
          SELECT DISTINCT ON (user_id) user_id, vless_uuid
            FROM xout_node_users
           ORDER BY user_id, provisioned_at ASC
        ) sub
       WHERE sub.user_id = u.id
         AND u.vless_uuid IS NULL
    $migrate$;
  END IF;
END $$;
-- Generate fresh UUIDs for any remaining users.
UPDATE auth_users SET vless_uuid = gen_random_uuid()
  WHERE vless_uuid IS NULL;
ALTER TABLE auth_users ALTER COLUMN vless_uuid SET NOT NULL;
ALTER TABLE auth_users
  ALTER COLUMN vless_uuid SET DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_vless_uuid
  ON auth_users (vless_uuid);

-- 4. subscription_token (TEXT, NOT NULL, UNIQUE).
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS subscription_token TEXT;
UPDATE auth_users SET subscription_token = _gen_url_safe_token()
  WHERE subscription_token IS NULL OR subscription_token = '';
ALTER TABLE auth_users ALTER COLUMN subscription_token SET NOT NULL;
ALTER TABLE auth_users
  ALTER COLUMN subscription_token SET DEFAULT _gen_url_safe_token();
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_subscription_token
  ON auth_users (subscription_token);

-- 5. Every active user must have a password row (the user-system goal
-- says "username, email, password" are all required). For migrated rows
-- without one, write a random argon2-shaped placeholder hash that no
-- real password can ever match. Operator can later set a real password
-- via the admin UI.
INSERT INTO auth_passwords (user_id, argon2_hash)
  SELECT u.id,
    '$argon2id$v=19$m=65536,t=3,p=4$' ||
    encode(extensions.gen_random_bytes(16), 'base64') || '$' ||
    encode(extensions.gen_random_bytes(32), 'base64')
    FROM auth_users u
   WHERE NOT EXISTS (
     SELECT 1 FROM auth_passwords p WHERE p.user_id = u.id
   );

-- 6. Drop subscriptions.subscription_token. The /sub URL is per-user
-- now; one user, one URL, all active xout subs aggregated server-side.
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subscription_token;

-- 7. Drop legacy tables. Order matters: drop child FKs first.
DROP TABLE IF EXISTS xout_traffic_daily;
DROP TABLE IF EXISTS xout_node_tokens;
DROP TABLE IF EXISTS xout_tokens;
DROP TABLE IF EXISTS xout_node_users;

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

-- Products: service_code column (2026-05-09) --------------------------------
-- Each product now belongs to exactly one platform service:
--   'chat'     — AI subscription tiers (tier_*)
--   'xout'     — VPN/proxy packages (xout-*)
--   'platform' — any other infra-level product
-- Idempotent: ADD COLUMN IF NOT EXISTS + conditional UPDATE.
ALTER TABLE products ADD COLUMN IF NOT EXISTS service_code TEXT NOT NULL DEFAULT 'platform';

-- Backfill existing rows based on code prefix.
UPDATE products SET service_code = 'chat'
  WHERE service_code = 'platform' AND code LIKE 'tier_%';

UPDATE products SET service_code = 'xout'
  WHERE service_code = 'platform' AND code LIKE 'xout-%';

-- Index for service-filtered queries used by /api/products?service=chat.
CREATE INDEX IF NOT EXISTS idx_products_service_code ON products (service_code);

-- Commands palette ---------------------------------------------------------
-- Operator-facing button catalog for the admin SPA's #/commands page.
-- Replaces the old "write a .command shell script, double-click via
-- Finder, screenshot the terminal" loop with one-click forms backed by
-- audited backend endpoints. Lives on the home schema (the registry is
-- per-operator, not per-tenant).
--
-- ``schema``  — JSONB array of ``{name, label, type, required?, options?,
--               default?}`` entries describing the form the SPA renders.
-- ``exec``    — JSONB ``{kind: 'local-run' | 'service-deploy' | 'node-run'
--               | 'db-apply-schema' | 'db-run-sql' | 'admin-restart'
--               | 'local-git-commit-push' | 'local-repo-sync', args: {...},
--               timeout_s?: int}``. ``args`` is merged with the operator's
--               form values at run time (form values take precedence).
-- ``is_builtin`` — true for rows seeded from this file. Custom rows added
--               via the UI default to false. Builtins re-seed on every
--               apply-schema via INSERT ... ON CONFLICT (id) DO NOTHING,
--               so their definitions evolve over time without overwriting
--               operator edits.
CREATE TABLE IF NOT EXISTS commands_catalog (
  id            TEXT PRIMARY KEY,
  title         TEXT NOT NULL,
  description   TEXT,
  category      TEXT NOT NULL,
  schema        JSONB NOT NULL DEFAULT '[]'::jsonb,
  exec          JSONB NOT NULL,
  is_builtin    BOOLEAN NOT NULL DEFAULT FALSE,
  sort_order    INTEGER NOT NULL DEFAULT 100,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commands_catalog_category
  ON commands_catalog (category, sort_order, id);

-- One row per command invocation. Used for the "history" modal and the
-- "re-run with same args" affordance. ``stdout_head`` / ``stderr_head``
-- store the first 64 KiB of output (operator can see the full output in
-- the response of the original run, not in the audit log).
-- ON DELETE SET NULL preserves audit history when a catalog row is
-- removed: the historical run still tells the operator "something
-- ran with these args at this time", which matters for incident
-- review even after the command_id has been reaped.
CREATE TABLE IF NOT EXISTS command_runs (
  id            BIGSERIAL PRIMARY KEY,
  command_id    TEXT REFERENCES commands_catalog(id) ON DELETE SET NULL,
  args_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
  status        TEXT NOT NULL,
  exit_code     INTEGER,
  stdout_head   TEXT,
  stderr_head   TEXT,
  error_message TEXT,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at   TIMESTAMPTZ
);

-- Idempotent FK upgrade for command_runs tables created before the
-- ON DELETE SET NULL constraint was added (initial drop).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'command_runs_command_id_fkey'
      AND conrelid = 'command_runs'::regclass
  ) THEN
    ALTER TABLE command_runs
      ADD CONSTRAINT command_runs_command_id_fkey
      FOREIGN KEY (command_id) REFERENCES commands_catalog(id)
      ON DELETE SET NULL;
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_command_runs_recent
  ON command_runs (command_id, started_at DESC);

-- Builtin command seed. Idempotent: ``ON CONFLICT (id) DO NOTHING`` keeps
-- operator edits to a builtin row intact. To roll out an updated builtin
-- definition, bump the id (e.g. ``deploy-service-v2``) or have the
-- operator delete the old row.
INSERT INTO commands_catalog (id, title, description, category, schema, exec, is_builtin, sort_order)
VALUES
  -- Quick actions ---------------------------------------------------------
  ('restart-admin',
   'Restart admin',
   'os.execv the admin process. The SPA re-connects within ~5s.',
   'quick',
   '[]'::jsonb,
   '{"kind":"admin-restart","args":{}}'::jsonb,
   TRUE, 10),

  ('apply-schema',
   'Apply schema',
   'Run sql/schema.sql against a registered database. Idempotent — safe to re-run.',
   'quick',
   '[{"name":"db_id","label":"Database","type":"db_id","required":true}]'::jsonb,
   '{"kind":"db-apply-schema","args":{}}'::jsonb,
   TRUE, 20),

  ('run-sql',
   'Run SQL',
   'Execute a SQL statement against a registered database. Multiple statements separated by semicolons are allowed.',
   'db',
   '[{"name":"db_id","label":"Database","type":"db_id","required":true},
     {"name":"sql","label":"SQL","type":"textarea","required":true,"placeholder":"SELECT now();"}]'::jsonb,
   '{"kind":"db-run-sql","args":{}}'::jsonb,
   TRUE, 30),

  -- Free-form -------------------------------------------------------------
  ('free-form-run',
   'Free-form shell (host)',
   'Run a shell command on the host where admin runs (the operator''s Mac). 60s default timeout.',
   'free',
   '[{"name":"cmd","label":"Command","type":"textarea","required":true,"placeholder":"git log --oneline -5"},
     {"name":"cwd","label":"Working dir","type":"text","required":false,"placeholder":"defaults to repo root"}]'::jsonb,
   '{"kind":"local-run","args":{}}'::jsonb,
   TRUE, 100),

  ('node-run',
   'Free-form shell (remote node)',
   'Run a shell command on a managed node via the platform''s SSH mux.',
   'remote',
   '[{"name":"node_name","label":"Node","type":"node_name","required":true},
     {"name":"cmd","label":"Command","type":"textarea","required":true,"placeholder":"docker ps"}]'::jsonb,
   '{"kind":"node-run","args":{}}'::jsonb,
   TRUE, 110),

  -- Git workflows ---------------------------------------------------------
  ('git-commit-push-ssl-service',
   'Commit + push (ssl-service)',
   'Stage everything in the ssl-service main checkout, commit with the given message, and push to origin/main.',
   'git',
   '[{"name":"message","label":"Commit message","type":"text","required":true,"placeholder":"chore: …"},
     {"name":"paths","label":"Paths (blank = all)","type":"text","required":false,"placeholder":"src/foo.py docs/"}]'::jsonb,
   '{"kind":"local-git-commit-push","args":{"repo_path":"."}}'::jsonb,
   TRUE, 200),

  ('git-commit-push-chatbot',
   'Commit + push (chatbot submodule)',
   'Stage everything in service-source/chatbot, commit, and push to origin/main of the chatbot.git remote.',
   'git',
   '[{"name":"message","label":"Commit message","type":"text","required":true,"placeholder":"feat(chat): …"},
     {"name":"paths","label":"Paths (blank = all)","type":"text","required":false}]'::jsonb,
   '{"kind":"local-git-commit-push","args":{"repo_path":"service-source/chatbot"}}'::jsonb,
   TRUE, 210),

  ('git-bump-chatbot-submodule',
   'Bump chatbot submodule pointer',
   'cd into ssl-service, ``git add service-source/chatbot``, commit "chore: bump chatbot submodule to <sha>", push.',
   'git',
   '[]'::jsonb,
   '{"kind":"local-run","args":{"cmd":"set -e; cd service-source/chatbot && SHA=$(git rev-parse --short HEAD) && cd ../.. && git add service-source/chatbot && git commit -m \"chore: bump chatbot submodule to ${SHA}\" && git push origin main","cwd":"."}}'::jsonb,
   TRUE, 220),

  ('git-discard-and-pull-ssl-service',
   'Discard local + pull (ssl-service)',
   'Reset and clean the ssl-service working tree, then pull origin/main. Recovers from "uncommitted changes block deploy".',
   'git',
   '[]'::jsonb,
   '{"kind":"local-repo-sync","args":{"repo_path":".","branch":"main"}}'::jsonb,
   TRUE, 230),

  -- Service deploys -------------------------------------------------------
  ('deploy-service',
   'Deploy service (parametrised)',
   'Trigger a full deploy of a service. Optionally restrict to specific nodes; default uses the service''s default_node.',
   'deploy',
   '[{"name":"service_name","label":"Service","type":"service_name","required":true},
     {"name":"nodes","label":"Nodes (comma-separated, blank = default)","type":"text","required":false,"placeholder":"xcenter,us01"},
     {"name":"force_rebuild","label":"Force rebuild (--build --force-recreate)","type":"checkbox","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{}}'::jsonb,
   TRUE, 300),

  ('deploy-chat',
   'Deploy chat',
   'Deploy the chat service to its default node (xcenter).',
   'deploy',
   '[{"name":"force_rebuild","label":"Force rebuild","type":"checkbox","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{"service_name":"chat"}}'::jsonb,
   TRUE, 310),

  ('deploy-chatbot',
   'Deploy chatbot',
   'Deploy the chatbot service to its default node (xcenter).',
   'deploy',
   '[{"name":"force_rebuild","label":"Force rebuild","type":"checkbox","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{"service_name":"chatbot"}}'::jsonb,
   TRUE, 320),

  ('deploy-user',
   'Deploy user-service',
   'Deploy the user-service backend to xcenter.',
   'deploy',
   '[{"name":"force_rebuild","label":"Force rebuild","type":"checkbox","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{"service_name":"user"}}'::jsonb,
   TRUE, 330),

  ('deploy-user-center',
   'Deploy user-center',
   'Deploy the Next.js user-center frontend to xcenter.',
   'deploy',
   '[{"name":"force_rebuild","label":"Force rebuild","type":"checkbox","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{"service_name":"user-center"}}'::jsonb,
   TRUE, 340),

  ('deploy-xout',
   'Deploy xout',
   'Deploy the xout product loop to its default node.',
   'deploy',
   '[{"name":"nodes","label":"Nodes (comma-separated, blank = default)","type":"text","required":false}]'::jsonb,
   '{"kind":"service-deploy","args":{"service_name":"xout"}}'::jsonb,
   TRUE, 350),

  -- Remote node ops -------------------------------------------------------
  ('xcenter-docker-ps',
   'xcenter docker ps',
   'List running containers on xcenter.',
   'remote',
   '[]'::jsonb,
   '{"kind":"node-run","args":{"node_name":"xcenter","cmd":"docker ps --format ''table {{.Names}}\\t{{.Status}}\\t{{.Ports}}''"}}'::jsonb,
   TRUE, 400),

  ('xcenter-docker-logs',
   'xcenter docker logs',
   'Tail the last N lines of a container''s logs on xcenter.',
   'remote',
   '[{"name":"container","label":"Container","type":"text","required":true,"placeholder":"chat / chatbot / user / user-center / xout"},
     {"name":"tail","label":"Lines","type":"text","required":false,"placeholder":"100"}]'::jsonb,
   '{"kind":"node-run","args":{"node_name":"xcenter","cmd":"docker logs --tail ${tail:-100} ${container}"},"timeout_s":30}'::jsonb,
   TRUE, 410),

  ('xcenter-clear-orphan-chat',
   'xcenter: stop + remove orphan ''chat'' (lobehub) container',
   'Tear down the legacy lobehub ``chat`` container that was retired when chatbot took over chat.develop.cc.',
   'remote',
   '[]'::jsonb,
   '{"kind":"node-run","args":{"node_name":"xcenter","cmd":"docker stop chat 2>/dev/null; docker rm chat 2>/dev/null; echo done"}}'::jsonb,
   TRUE, 420)
ON CONFLICT (id) DO NOTHING;
