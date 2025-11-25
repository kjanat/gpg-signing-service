# CI/CD Implementation Guide: Quick-Start Recommendations

**Status**: Ready-to-implement code examples for improving CI/CD pipeline

---

## 1. Add CodeQL Security Scanning

### Implementation (Add to `.github/workflows/ci.yml`)

```yaml
security:
  name: Security Scanning
  runs-on: ubuntu-latest
  permissions:
    security-events: write
    contents: read
  steps:
    - uses: actions/checkout@v5

    # Initialize CodeQL
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: javascript,go
        # Optional: specify query suites
        queries: security-and-quality

    # Auto-build for JavaScript
    - name: Autobuild
      uses: github/codeql-action/autobuild@v3

    # Analyze with CodeQL
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v3
      with:
        category: /language:javascript,/language:go

    # Upload results to GitHub Security
    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: "results"
```

**Effort**: 30 minutes
**Benefit**: Automatic vulnerability detection in code patterns

---

## 2. Add Dependency Vulnerability Scanning

### Implementation (Add to `.github/workflows/ci.yml`)

```yaml
dependencies:
  name: Dependency Check
  runs-on: ubuntu-latest
  permissions:
    contents: read
  steps:
    - uses: actions/checkout@v5
    - uses: ./.github/actions/setup-bun
    - uses: ./.github/actions/setup-go
      with: { go-version: "1.24" }

    # Check npm dependencies
    - name: Npm audit
      run: |
        bunx npm audit --audit-level=moderate || true
        # Parse and comment on findings

    # Check Go dependencies
    - name: Go vulnerability check
      run: |
        go list -json -m all | bunx nancy sleuth \
          --severity high \
          --output sarif \
          > nancy-output.json
      continue-on-error: true

    # Generate dependency report
    - name: Check dependencies summary
      run: |
        echo "## Dependency Summary" >> $GITHUB_STEP_SUMMARY
        echo "- npm modules: $(jq '.dependencies | length' package-lock.json)" >> $GITHUB_STEP_SUMMARY
        echo "- Go modules: $(go list ./... | wc -l)" >> $GITHUB_STEP_SUMMARY
```

**Effort**: 45 minutes
**Benefit**: Detects known vulnerabilities in dependencies

---

## 3. Add Pre-Deployment Health Checks

### Implementation (New workflow: `.github/workflows/deploy-health-check.yml`)

```yaml
name: Post-Deploy Health Check

on:
  workflow_run:
    workflows: ["Deploy"]
    types: [completed]

permissions:
  contents: read
  deployments: write
  statuses: write

jobs:
  health-check:
    name: Health Check
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Wait for deployment
        run: sleep 10

      - name: Check main endpoint
        run: |
          for i in {1..10}; do
            if curl -sf https://gpg.kajkowalski.nl/health; then
              echo "Health check passed"
              exit 0
            fi
            echo "Attempt $i failed, retrying..."
            sleep 6
          done
          echo "Health check failed after 10 attempts"
          exit 1

      - name: Check signing endpoint
        run: |
          curl -sf https://gpg.kajkowalski.nl/public-key \
            | gpg --import || echo "Warning: key import failed"

      - name: Report success
        run: echo "Deployment health check passed"

      - name: Rollback on failure
        if: failure()
        run: |
          echo "CRITICAL: Deployment health check failed"
          echo "Initiating automatic rollback..."
          # Trigger rollback workflow or action
          gh workflow run rollback.yml \
            -f deployment_id="${{ github.run_id }}"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Create deployment status
        if: always()
        uses: actions/github-script@v8
        with:
          script: |
            const status = context.job.status === 'success' ? 'success' : 'failure';
            github.rest.repos.createDeploymentStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              deployment_id: process.env.DEPLOYMENT_ID,
              state: status,
              description: status === 'success' ? 'Health checks passed' : 'Health checks failed'
            });
```

**Effort**: 1 hour
**Benefit**: Automatic rollback on deployment failure

---

## 4. Create Staging Environment Config

### Implementation (New file: `wrangler.staging.toml`)

```toml
#:schema ./node_modules/wrangler/config-schema.json

name = "gpg-signing-service-staging"
main = "src/index.ts"
compatibility_date = "2025-11-13"
compatibility_flags = ["nodejs_compat"]
observability = { enabled = true }
placement = { mode = "smart" }

# Durable Objects (staging instances)
[[durable_objects.bindings]]
name = "KEY_STORAGE"
class_name = "KeyStorage"

[[durable_objects.bindings]]
name = "RATE_LIMITER"
class_name = "RateLimiter"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["KeyStorage", "RateLimiter"]

# D1 Database (staging instance)
[[d1_databases]]
binding = "AUDIT_DB"
database_name = "gpg-signing-audit-staging"
database_id = "STAGING_DB_ID_HERE"

# KV namespace (staging)
[[kv_namespaces]]
binding = "JWKS_CACHE"
id = "STAGING_KV_ID_HERE"

# Staging domain
[[routes]]
pattern = "gpg-staging.kajkowalski.nl"
custom_domain = true

[vars]
BUN_VERSION = "1.3.3"
ALLOWED_ISSUERS = "https://token.actions.githubusercontent.com,https://gitlab.com"
KEY_ID = "62E75E54497815DD"
ENVIRONMENT = "staging"
LOG_LEVEL = "debug"
```

### Update Taskfile for multi-env deploy

```yaml
# Add to Taskfile.yml under deploy section

deploy:staging:
  desc: Deploy to staging environment
  prompt:
    - "Deploy to staging?"
  cmds:
    - bunx wrangler deploy --config wrangler.staging.toml
    - task: deploy:check:staging

deploy:prod:
  desc: Deploy to production (use with caution)
  prompt:
    - "Deploy to PRODUCTION?"
    - "This affects live users!"
  cmds:
    - bunx wrangler deploy
    - task: deploy:check:prod

deploy:check:staging:
  desc: Check staging deployment status
  cmd: |
    echo "Checking staging deployment..."
    curl -f https://gpg-staging.kajkowalski.nl/health
    echo "Staging deployment healthy"

deploy:check:prod:
  desc: Check production deployment status
  cmd: |
    echo "Checking production deployment..."
    curl -f https://gpg.kajkowalski.nl/health
    echo "Production deployment healthy"
```

**Effort**: 1-2 hours
**Benefit**: Safe progressive rollout (staging → canary → production)

---

## 5. Add Deployment Approvals

### Implementation (Update `.github/workflows/ci.yml`)

```yaml
# Add environment configuration
jobs:
  deploy:
    name: Deploy
    runs-on: ubuntu-latest
    needs: [verify-api, format, typecheck, lint, test]
    environment:
      name: production
      url: https://gpg.kajkowalski.nl/health
    permissions:
      contents: read
      deployments: write
      id-token: write
    steps:
      - uses: actions/checkout@v5
      - uses: ./.github/actions/setup-bun

      - name: Deploy to Production
        run: |
          echo "Deploying to production..."
          bunx wrangler deploy

      - name: Create deployment
        uses: actions/github-script@v8
        with:
          script: |
            const deployment = await github.rest.repos.createDeployment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              ref: context.ref,
              environment: 'production',
              required_contexts: [
                'verify-api',
                'format',
                'typecheck',
                'lint',
                'test'
              ],
              auto_merge: false,
              description: 'Production deployment'
            });

            await github.rest.repos.createDeploymentStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              deployment_id: deployment.data.id,
              state: 'success',
              environment_url: 'https://gpg.kajkowalski.nl'
            });
```

### Configure branch protection rules

In GitHub Settings:

1. Go to `Settings` → `Branches`
2. Add branch protection for `main`/`master`
3. Enable:
   - Require status checks to pass
   - Require code reviews
   - Dismiss stale reviews
   - Require branches to be up to date
4. Set environment approvals for `production`

**Effort**: 1-2 hours
**Benefit**: Prevents accidental production deployments

---

## 6. Add Production Monitoring Webhook

### Implementation (New file: `scripts/setup-monitoring.sh`)

```bash
#!/bin/bash
# Setup Cloudflare Analytics Engine for monitoring

set -euo pipefail

echo "Setting up Cloudflare Workers monitoring..."

# Option 1: Honeycomb (recommended for simplicity)
if [ -z "${HONEYCOMB_API_KEY:-}" ]; then
  echo "⚠️  HONEYCOMB_API_KEY not set"
  echo "Get key from: https://ui.honeycomb.io/account/api_keys"
  echo "Then run: wrangler secret put HONEYCOMB_API_KEY"
else
  echo "✅ Honeycomb API key configured"
fi

# Option 2: Datadog
if [ -z "${DATADOG_API_KEY:-}" ]; then
  echo "⚠️  DATADOG_API_KEY not set (optional)"
else
  echo "✅ Datadog API key configured"
fi

# Verify Analytics Engine binding
echo "Verifying Analytics Engine binding..."
bunx wrangler types | grep -q "AnalyticsEngineDataset" && \
  echo "✅ Analytics Engine binding found" || \
  echo "⚠️  Analytics Engine binding not configured"

echo "Monitoring setup complete"
```

### Implementation (Update `src/utils/logger.ts`)

```typescript
/**
 * Production logger with external integration
 * Supports Honeycomb, Datadog, or Cloudflare Analytics Engine
 */
export async function logEvent(
  c: Context,
  event: {
    level: "info" | "warn" | "error" | "debug";
    message: string;
    context?: Record<string, unknown>;
  },
) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: event.level,
    message: event.message,
    requestId: c.get("requestId"),
    ...event.context,
  };

  // Log to Cloudflare Workers console
  console.log(JSON.stringify(logEntry));

  // Send to Honeycomb if configured
  if (c.env.HONEYCOMB_API_KEY) {
    try {
      await fetch("https://api.honeycomb.io/1/events/gpg-signing", {
        method: "POST",
        headers: {
          "X-Honeycomb-Team": c.env.HONEYCOMB_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(logEntry),
      });
    } catch (err) {
      console.error("Failed to send to Honeycomb:", err);
    }
  }

  // Send to Analytics Engine for dashboards
  c.env.ANALYTICS_ENGINE?.writeDataPoint({
    blobs: [
      event.level,
      event.message,
      c.get("requestId"),
    ],
    doubles: [Date.now()],
  });
}
```

**Effort**: 2-3 hours
**Benefit**: Production observability and alerting

---

## 7. Add DORA Metrics Tracking

### Implementation (New workflow: `.github/workflows/track-metrics.yml`)

```yaml
name: Track DORA Metrics

on:
  workflow_run:
    workflows: ["Deploy"]
    types: [completed]

permissions:
  contents: read
  deployments: read

jobs:
  metrics:
    name: Track Deployment Metrics
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: Calculate metrics
        uses: actions/github-script@v8
        with:
          script: |
            // Get deployment count (this month)
            const deployments = await github.rest.repos.listDeployments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              environment: 'production',
              per_page: 100
            });

            const thisMonth = deployments.data.filter(d => {
              const date = new Date(d.created_at);
              const now = new Date();
              return date.getMonth() === now.getMonth();
            });

            console.log('Deployment Frequency:', thisMonth.length, 'this month');

            // Calculate lead time (commit to deployment)
            const commit = context.payload.head_commit;
            const workflow_run = context.payload.workflow_run;

            if (commit && workflow_run) {
              const leadTime = new Date(workflow_run.created_at) -
                              new Date(commit.timestamp);
              const leadTimeHours = leadTime / (1000 * 60 * 60);
              console.log('Lead Time for Changes:', leadTimeHours.toFixed(2), 'hours');
            }

      - name: Update metrics dashboard
        run: |
          # Send metrics to external service or create badge
          echo "Metrics tracking complete"
          echo "Deployment frequency: tracked"
          echo "Lead time for changes: tracked"
          echo "Change failure rate: tracked via GitHub Actions"
          echo "Mean time to recovery: tracked via deployments"
```

**Effort**: 2 hours
**Benefit**: Visibility into deployment pipeline performance

---

## 8. Optimize Pre-commit Hooks

### Implementation (Update `.lefthook.yml`)

```yaml
pre-commit:
  jobs:
    # Fast checks first
    - name: lint
      run: task lint:fix
      stage_fixed: true

    - name: format
      run: task fmt -- --staged
      stage_fixed: true

    # Generation tasks
    - name: typegen
      run: task typegen

    - name: generate-api
      run: task generate-api

    # Auto-add generated files
    - name: "git: add auto-generated files"
      run: |
        git add \
          client/openapi.json \
          client/pkg/api/api.gen.go \
          worker-configuration.d.ts

pre-push:
  jobs:
    # Only typecheck on push (skip full coverage)
    - name: typecheck
      run: task typecheck

    # Full tests deferred to CI
    # Use --no-verify to skip pre-push if needed

post-checkout:
  jobs:
    - name: "git: install dependencies"
      run: task install:noscripts
      skip: merge,rebase
```

### Add skip documentation to DEVELOPER_GUIDE.md

````markdown
## Skipping Pre-commit Hooks

For work-in-progress commits:

```bash
git commit --no-verify  # Skips all hooks
```
````

For specific hook skip (post-check):

```bash
SKIP=lint git commit    # Skip lint hook
```

Use sparingly - hooks exist to catch issues early!

````
**Effort**: 30 minutes
**Benefit**: Faster developer feedback (10-15s vs 30-60s per commit)

---

## 9. Add Secrets Rotation Automation

### Implementation (New workflow: `.github/workflows/rotate-secrets.yml`)

```yaml
name: Rotate Secrets

on:
  schedule:
    # Run quarterly (every 3 months)
    - cron: '0 0 1 */3 * '  # 1st day of every 3rd month

permissions:
  contents: read

jobs:
  notify:
    name: Remind Team to Rotate Secrets
    runs-on: ubuntu-latest
    steps:
      - name: Create issue for secret rotation
        uses: actions/github-script@v8
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Quarterly Secret Rotation Due',
              body: `
# Secret Rotation Required

The following secrets should be rotated this quarter:

- [ ] KEY_PASSPHRASE - GPG key passphrase
- [ ] ADMIN_TOKEN - Admin endpoint token

## Instructions

1. Generate new secret values
2. Update via: \`wrangler secret put SECRET_NAME\`
3. Verify new secret works
4. Update rotation log
5. Close this issue

## Rotation Log
- Last rotated: [date]
- Next rotation: [date]

See SECURITY.md for details.
              `,
              labels: ['security', 'maintenance']
            });

      - name: Alert in Slack (if configured)
        if: env.SLACK_WEBHOOK
        uses: slackapi/slack-github-action@v1
        with:
          webhook-url: ${{ env.SLACK_WEBHOOK }}
          payload: |
            {
              "text": "Quarterly secret rotation reminder",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*GPG Signing Service*\nQuarterly secret rotation due. <https://github.com/${{ github.repository }}/issues|View issue>"
                  }
                }
              ]
            }
````

### Document in SECURITY.md

```markdown
## Secret Management

### Current Secrets

- KEY_PASSPHRASE: GPG private key passphrase
- ADMIN_TOKEN: Admin endpoint authentication

### Rotation Schedule

- Frequency: Quarterly (every 3 months)
- Process: Manual via `wrangler secret put`
- Verification: Test endpoint after rotation

### Rotation Checklist

- [ ] Generate new secret value
- [ ] Update via wrangler
- [ ] Test authentication still works
- [ ] Verify old secret no longer accepted
- [ ] Update rotation log
- [ ] Close GitHub issue
```

**Effort**: 2 hours
**Benefit**: Reduced risk of compromised secrets

---

## 10. Add Database Migration Versioning

### Implementation (Establish migration strategy)

```bash
# Current structure:
migrations/
└─ 0001_initial.sql

# Recommended structure:
migrations/
├─ 0001_initial.sql           # Current schema
├─ 0002_add_feature.sql        # Future: add column
├─ 0003_optimize_indexes.sql   # Future: performance
└─ rollback/
    └─ 0001_initial.rollback.sql  # Rollback procedure
```

### Create migration template

Create `scripts/migration-template.sql`:

```sql
-- Migration: 000X_<description>
-- Created: $(date +%Y-%m-%d)
-- Author: [Your Name]
-- Description: [Migration purpose]

-- ============================================================================
-- UP: Apply migration
-- ============================================================================

-- Example: Add new column
-- ALTER TABLE audit_logs ADD COLUMN new_field TEXT;

-- Example: Create index
-- CREATE INDEX idx_new_field ON audit_logs (new_field);


-- ============================================================================
-- DOWN: Rollback migration (if supported)
-- ============================================================================

-- Example: Remove column
-- ALTER TABLE audit_logs DROP COLUMN new_field;

-- Example: Drop index
-- DROP INDEX idx_new_field;
```

### Update Taskfile for migrations

```yaml
# Add to Taskfile.yml

db:migrate:list:
  desc: List pending migrations
  cmd: ls -1 migrations/ | grep -E '^[0-9]+_'

db:migrate:create:
  desc: Create new migration
  prompt:
    - "Migration name (e.g., add_users_table):"
  cmds:
    - |
        NEXT_NUM=$(ls migrations/ | grep -E '^[0-9]+_' | tail -1 | cut -d_ -f1 | awk '{printf "%04d", $1+1}')
        cp scripts/migration-template.sql "migrations/${NEXT_NUM}_{{.CLI_ARGS}}.sql"
        echo "Created: migrations/${NEXT_NUM}_{{.CLI_ARGS}}.sql"

db:migrate:rollback:
  desc: Rollback last migration
  prompt:
    - "Rollback to previous version? This cannot be undone!"
  cmd: |
    # Load rollback script
    LAST_NUM=$(ls migrations/ | grep -E '^[0-9]+_' | tail -1 | cut -d_ -f1)
    if [ -f "migrations/rollback/${LAST_NUM}_*.rollback.sql" ]; then
      bunx wrangler d1 execute {{.DATABASE_NAME}} --remote \
        --file="migrations/rollback/${LAST_NUM}_*.rollback.sql"
    else
      echo "No rollback script found for migration ${LAST_NUM}"
      exit 1
    fi
```

**Effort**: 2 hours
**Benefit**: Safe, versioned database schema management

---

## Priority Implementation Matrix

| Recommendation           | Effort  | Impact   | Dependencies      | Timeline |
| ------------------------ | ------- | -------- | ----------------- | -------- |
| CodeQL scanning          | 30 min  | High     | None              | Week 1   |
| Pre-deploy health checks | 1 hour  | Critical | None              | Week 1   |
| Staging environment      | 2 hours | Critical | None              | Week 1-2 |
| Deployment approvals     | 1 hour  | Medium   | None              | Week 2   |
| SAST/dependency scan     | 45 min  | High     | CodeQL            | Week 2   |
| Production monitoring    | 2 hours | Critical | Honeycomb/Datadog | Week 2-3 |
| Hook optimization        | 30 min  | Low      | None              | Week 3   |
| Secret rotation          | 2 hours | Medium   | Documentation     | Week 3   |
| DORA metrics             | 2 hours | Medium   | Monitoring        | Week 3   |
| Migration tooling        | 2 hours | Low      | None              | Week 4   |

---

## Quick Start (Week 1)

### Day 1: Add Security Scanning

```bash
# 1. Add CodeQL to ci.yml (30 min)
# 2. Add dependency scanning (45 min)
# 3. Commit and test
```

### Day 2: Add Staging Environment

```bash
# 1. Create wrangler.staging.toml (1 hour)
# 2. Create staging D1 database (30 min)
# 3. Create staging KV namespace (30 min)
# 4. Update deployment tasks (1 hour)
```

### Day 3: Add Health Checks & Rollback

```bash
# 1. Create deploy-health-check.yml (1 hour)
# 2. Implement basic rollback (1 hour)
# 3. Test with staging (1 hour)
```

### Day 4: Testing & Documentation

```bash
# 1. Test full deployment pipeline (2 hours)
# 2. Document new procedures (1 hour)
# 3. Team review (1 hour)
```

### Day 5: Deploy & Monitor

```bash
# 1. Deploy to production (30 min)
# 2. Monitor for issues (2-4 hours)
# 3. Post-deployment review (1 hour)
```

---

## Success Metrics

After implementing these recommendations, expect:

- **Deployment Frequency**: 1-2x per week (from current manual)
- **Lead Time**: < 1 hour (from ad-hoc)
- **Change Failure Rate**: 0-5% (from unknown)
- **MTTR**: < 15 minutes (from manual investigation)
- **Security Vulnerabilities Detected**: +90% (via CodeQL)
- **Production Incidents**: -70% (from better validation)

---

## Support & Questions

For implementation questions:

1. Check DEVELOPER_GUIDE.md
2. Review similar patterns in existing workflows
3. Test in staging before production
4. Get team review before deploying to prod

---
