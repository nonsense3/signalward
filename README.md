# SignalWard

SignalWard is a security workspace for Git repository scanning, suspicious-message review, and signed evidence receipts.

- [Architecture](architecture.md)
- [Design](design.md)
- [Implementation plan](implementation.md)
- [Project memory](memory.md)
- [Skills and MCP](skills.md)

Run the local landing page with Node.js 24. It uses the deterministic policy to evaluate a synthetic finding.

```sh
npm run dev
```

Open the URL printed in the terminal. The server tries port 3000 first and selects an available local port if 3000 is occupied. Set the `PORT` environment variable to require a specific port. No package installation is required for this preview.

Run the policy tests with:

```sh
node --test tests/policy.test.ts
```
