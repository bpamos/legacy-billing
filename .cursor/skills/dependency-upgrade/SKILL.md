---
name: dependency-upgrade
description: Use whenever upgrading a dependency to remediate a security advisory.
---
# Dependency Security Upgrade Playbook
1. The prompt provides: package, ecosystem, current version, REQUIRED fixed version, advisory IDs.
2. Update package.json to EXACTLY the fixed version. Regenerate the lockfile with npm install.
   NEVER use --force or --legacy-peer-deps; if resolution fails, stop and report.
3. Run the full test suite. If failures:
   a. Read the dependency's CHANGELOG/migration guide for the major version range crossed.
   b. Fix APPLICATION CODE and TESTS to conform to the new API.
   c. NEVER delete tests, mark tests skipped, or weaken assertions to force green.
   d. If a failure encodes a business rule that the upgrade genuinely violates, STOP:
      summarize the conflict, do not paper over it, and end reporting the blocker.
4. Re-run tests until green (or blocked per 3d).
5. PR body MUST contain: advisory IDs; old → new version; every code change with one-line
   rationale; test results summary (counts before/after); any warnings from install.
6. Commit style: conventional commits, scope = package name (e.g., "fix(deps): …").
