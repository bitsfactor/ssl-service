# Copy to `.env` for local dev. The platform writes its own `.env` on the
# target node at deploy time; this file is purely a hint for what the
# service consumes.

PORT={{port}}
LOG_LEVEL=info
TZ=Asia/Shanghai

# Reserved for the platform's billing sink. Leave unset for noop.
# BILLING_SINK_URL=https://billing.bitsfactor.com/events
