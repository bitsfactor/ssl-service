# Service deployment manifest — read by the ssl-service admin platform.
#
# Drop this file at the root of the repo. The platform clones it on the
# target node, validates required env, writes a fresh `.env`, then runs
# `docker compose up -d --build`. Healthcheck is verified before the
# deploy is marked successful.
#
# DO NOT change the `service` name, the `exposed_ports` list, or the
# healthcheck `url` after the service has been registered — the routes
# layer and the cert provisioning depend on them. Everything else is
# yours to tune.

service: {{name}}
runtime: compose
compose_file: docker-compose.yml
install_dir_template: /opt/{name}

required_env: []

defaults:
  PORT: "{{port}}"
  LOG_LEVEL: info
  TZ: Asia/Shanghai

# Sensitive values pulled from system_config at deploy time. Add entries
# like `{ env: DATABASE_URL, from: system_config:database_urls.production }`
# when the service needs platform-managed secrets.
secrets: []

exposed_ports:
  - {{port}}

healthcheck:
  url: http://localhost:${PORT}/health
  expect_status: 200
  timeout_seconds: 30
  retries: 6
  interval_seconds: 5

depends_on: []

hooks:
  pre_deploy: scripts/pre_deploy.sh
  post_deploy: scripts/post_deploy.sh

volumes:
  - /opt/{name}/data
  - /opt/{name}/logs
