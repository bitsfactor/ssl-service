services:
  {{name}}:
    build: .
    image: {{name}}:local
    container_name: {{name}}
    restart: unless-stopped
    env_file:
      - .env
    # The host port (left of the colon) is what the routes layer points
    # at — DO NOT change it without coordinating with the routes config.
    # The container port (right of the colon) must match the PORT env
    # the app actually binds to.
    ports:
      - "{{port}}:${PORT}"
    volumes:
      - /opt/{{name}}/data:/app/data
      - /opt/{{name}}/logs:/app/logs
