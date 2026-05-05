# Product manifest — read by the ssl-service products catalog.
#
# Whatever you put here is what users see on the company homepage when
# this service is enabled. Keep `slug` stable forever (it's in the
# public URL); everything else is editable.

product:
  enabled: false                # flip to true to publish to homepage
  visibility: public            # public | beta | private
  slug: {{name}}
  display_name: {{display_name}}
  tagline: ""
  icon: ""                      # emoji or absolute image URL
  category: ""                  # group on homepage; pick once and stay
  entry_url: https://{{domain}}/
  preview_image: ""             # path relative to repo root or absolute URL
  status: active                # active | maintenance | retired

  # Reserved for the future user/billing system. Today these are no-ops;
  # the service code already reads X-User-Id headers and calls
  # report_usage(), so flipping these later requires no code change.
  auth:
    required: false
  pricing:
    tier: free                  # free | metered | pro
    # usage_event: ""           # the report_usage() event to count
