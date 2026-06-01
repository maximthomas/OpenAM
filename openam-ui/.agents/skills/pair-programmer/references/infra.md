# Infrastructure Reference — Pair Programmer

## Docker

**Minimal, layered Dockerfile:**
```dockerfile
# Use specific version tags — never `latest`
FROM python:3.12-slim

WORKDIR /app

# Copy dependency files first (maximizes layer cache)
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev

# Then copy source code
COPY src/ ./src/

# Non-root user (security best practice)
RUN useradd -m appuser
USER appuser

# Use exec form (not shell form) for CMD/ENTRYPOINT
CMD ["python", "-m", "src.main"]
```

**Multi-stage builds to minimize image size:**
```dockerfile
FROM golang:1.22 AS builder
WORKDIR /build
COPY . .
RUN go build -o app ./cmd/server

FROM gcr.io/distroless/base-debian12
COPY --from=builder /build/app /app
CMD ["/app"]
```

**Common Dockerfile mistakes:**
- `apt-get install` without `rm -rf /var/lib/apt/lists/*` (bloated image)
- Running as root (security risk)
- `COPY . .` before dependency installation (kills cache on every code change)
- `latest` tag (non-deterministic builds)
- Secrets in `ENV` or `ARG` (visible in image layers)

---

## Docker Compose

```yaml
version: "3.9"
services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}   # from .env, not hardcoded
    depends_on:
      db:
        condition: service_healthy     # wait for health, not just start
    restart: unless-stopped

  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

**Always use `depends_on` with `condition: service_healthy` for stateful services.**

---

## Kubernetes

**Resource requests and limits are required in production:**
```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "500m"
# Without requests: scheduler can't make good decisions
# Without limits: a runaway pod can starve the node
```

**Liveness vs Readiness vs Startup probes:**
```yaml
livenessProbe:    # restart container if fails (is the process healthy?)
  httpGet:
    path: /healthz
    port: 8080
  failureThreshold: 3
  periodSeconds: 10

readinessProbe:   # remove from service if fails (ready to serve traffic?)
  httpGet:
    path: /ready
    port: 8080
  failureThreshold: 2
  periodSeconds: 5

startupProbe:     # allow slow startup (don't kill before app is ready)
  httpGet:
    path: /healthz
    port: 8080
  failureThreshold: 30
  periodSeconds: 10
```

**ConfigMaps for config, Secrets for credentials:**
```yaml
# Never put secrets in ConfigMaps or env vars in plain YAML
# Use: Kubernetes Secrets + RBAC, or external secret management (Vault, AWS SSM)
envFrom:
  - secretRef:
      name: app-secrets
```

**Always set `rollingUpdate` strategy:**
```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 0    # never take pods down before new ones are ready
    maxSurge: 1          # allow 1 extra pod during rollout
```

---

## Terraform

**Structure:**
```
infra/
├── main.tf
├── variables.tf
├── outputs.tf
├── versions.tf          # pin provider versions
└── modules/
    └── vpc/
        ├── main.tf
        └── variables.tf
```

**Pin versions to avoid drift:**
```hcl
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"   # allow patch updates, not major
    }
  }
}
```

**Remote state — always:**
```hcl
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "tf-state-lock"
  }
}
```

**Never commit `.tfstate` files. Use `terraform.tfvars` for local overrides, not for secrets.**

**Common Terraform mistakes:**
- Using `count` for conditionally creating resources (use `for_each` — cleaner diffs)
- Not using `lifecycle { prevent_destroy = true }` for databases and stateful resources
- Hardcoded AMI IDs or instance types (use variables)
- Forgetting to `terraform plan` before `apply` in CI

---

## CI/CD Best Practices

**Pipeline stages: lint → test → build → deploy:**
```yaml
# GitHub Actions example
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - run: pip install -e ".[dev]"
      - run: pytest --cov --cov-fail-under=80

  build:
    needs: test
    steps:
      - uses: docker/build-push-action@v5
        with:
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Secrets in CI — use the secret store, not hardcoded:**
```yaml
env:
  DATABASE_URL: ${{ secrets.DATABASE_URL }}  # GitHub Secrets, not plaintext
```

**Immutable image tags — always tag with commit SHA, not branch name.**

**Deployment verification — always run a smoke test after deploy.**

---

## Observability Checklist

Before a service is "production ready," it should have:

- [ ] Structured JSON logging (not freeform strings)
- [ ] Log levels used correctly (DEBUG for dev, INFO for normal ops, ERROR for actionable failures)
- [ ] Request tracing (correlation ID on every request)
- [ ] Metrics: request rate, error rate, latency (p50, p95, p99)
- [ ] Health endpoints: `/healthz` (liveness) and `/ready` (readiness)
- [ ] Alerts on error rate spike and latency degradation
- [ ] Runbook for common failure modes
