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

ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes (enabled);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);

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
