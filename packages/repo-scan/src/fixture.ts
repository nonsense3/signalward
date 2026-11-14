import type { SourceFile } from "./index.ts";

/**
 * Synthetic repository used by the demo and the sample endpoint. Credential-shaped values are assembled at
 * runtime from inert pieces so this source file never contains a scannable token. None of them are real.
 */
export function syntheticRepository(): SourceFile[] {
  const join = (...pieces: string[]) => pieces.join("");
  const awsId = join("AKIA", "SYNTHETIC", "EXAMPLE");
  const ghToken = join("ghp", "_", "Synthetic0Fixture0Token0", "000000000000");
  const dbPassword = join("fixture", "-Pa55-", "q8Zr");

  return [
    {
      path: "fixtures/demo.env",
      content: [
        "# Synthetic fixture for SignalWard. Not a real credential.",
        "NODE_ENV=production",
        `AWS_ACCESS_KEY_ID=${awsId}`,
        `DATABASE_URL=postgres://app:${dbPassword}@db.internal:5432/app`,
        "SESSION_SECRET=${SESSION_SECRET}",
      ].join("\n"),
    },
    {
      path: "src/deploy.ts",
      content: [
        "export async function publish() {",
        `  const token = "${ghToken}";`,
        "  return fetch(\"https://api.github.com/repos/acme/app/releases\", { headers: { authorization: `token ${token}` } });",
        "}",
      ].join("\n"),
    },
    {
      path: "package-lock.json",
      content: JSON.stringify({
        name: "acme-app",
        lockfileVersion: 3,
        packages: {
          "": { name: "acme-app", version: "1.0.0" },
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/minimist": { version: "1.2.5" },
          "node_modules/express": { version: "4.21.2" },
        },
      }, null, 2),
    },
    {
      path: ".github/workflows/triage.yml",
      content: [
        "name: triage",
        "on: pull_request_target",
        "permissions: write-all",
        "jobs:",
        "  label:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - uses: some-org/labeler@v2",
        "      - run: |",
        "          echo \"Triaging ${{ github.event.pull_request.title }}\"",
        "          curl -fsSL https://example.com/install.sh | bash",
      ].join("\n"),
    },
    { path: "README.md", content: "# acme-app\n\nSynthetic repository for SignalWard demos.\n" },
  ];
}

/** The same repository after remediation: the fixture should pass. */
export function remediatedRepository(): SourceFile[] {
  return [
    { path: "fixtures/demo.env", content: "NODE_ENV=production\nAWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\nDATABASE_URL=${DATABASE_URL}\n" },
    { path: "src/deploy.ts", content: "export async function publish(token = process.env.GITHUB_TOKEN) {\n  return token;\n}\n" },
    { path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.21" } } }) },
  ];
}
