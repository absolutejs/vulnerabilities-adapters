# AbsoluteJS Vulnerability Adapters

Feed and storage adapters for
[`@absolutejs/vulnerabilities`](https://github.com/absolutejs/vulnerabilities).
Each adapter remains an independently versioned npm package; this repository is
their source monorepo.

## Packages

| Workspace | Package | Role |
| --- | --- | --- |
| `epss/` | `@absolutejs/vulnerabilities-epss` | FIRST EPSS scoring feed |
| `kev/` | `@absolutejs/vulnerabilities-kev` | CISA Known Exploited Vulnerabilities feed |
| `osv/` | `@absolutejs/vulnerabilities-osv` | OSV advisory feed |
| `postgres/` | `@absolutejs/vulnerabilities-postgres` | PostgreSQL persistence |
| `ubuntu/` | `@absolutejs/vulnerabilities-ubuntu` | Canonical Ubuntu advisory feed |

The npm package names and version histories are unchanged by the move into this
monorepo.

## Development

```sh
bun install
bun run typecheck
bun run test
bun run build
```

Each workspace retains its own license and changelog.
