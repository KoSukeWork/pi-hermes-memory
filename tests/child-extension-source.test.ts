import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  normalizeChildExtensionSource,
  normalizeChildExtensionSources,
} from "../src/child-extension-source.js";

describe("normalizeChildExtensionSource", () => {
  it("accepts npm, git, and GitHub HTTPS package sources", () => {
    assert.equal(normalizeChildExtensionSource("npm:@example/provider-extension@1.0.0"), "npm:@example/provider-extension@1.0.0");
    assert.equal(normalizeChildExtensionSource("git:github.com/example/provider-extension@v1"), "git:github.com/example/provider-extension@v1");
    assert.equal(normalizeChildExtensionSource("git:git@github.com:example/provider-extension"), "git:git@github.com:example/provider-extension");
    assert.equal(normalizeChildExtensionSource("https://github.com/example/provider-extension@v1"), "https://github.com/example/provider-extension@v1");
  });

  it("rejects control characters, parent segments, and non-allowlisted schemes", () => {
    assert.equal(normalizeChildExtensionSource("npm:foo\nbar"), undefined);
    assert.equal(normalizeChildExtensionSource("../escape.ts"), undefined);
    assert.equal(normalizeChildExtensionSource("javascript:alert(1)"), undefined);
    assert.equal(normalizeChildExtensionSource("http://evil.example/extension.ts"), undefined);
    assert.equal(normalizeChildExtensionSource("file:///tmp/extension.ts"), undefined);
    assert.equal(normalizeChildExtensionSource("npm:foo/../../../etc"), undefined);
    assert.equal(normalizeChildExtensionSource("git:gitlab.com/example/provider"), undefined);
  });

  it("keeps local paths that do not exist unless existence is required", async () => {
    const missing = path.join(os.tmpdir(), "pi-missing-child-extension.ts");
    assert.equal(normalizeChildExtensionSource(missing), missing);
    assert.equal(normalizeChildExtensionSource(missing, { requireLocalExists: true }), undefined);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pi-child-source-"));
    const existing = path.join(dir, "adapter.ts");
    await fs.writeFile(existing, "export default () => {};");
    try {
      assert.equal(
        normalizeChildExtensionSource(existing, { requireLocalExists: true }),
        path.resolve(existing),
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("deduplicates trusted sources", () => {
    assert.deepStrictEqual(
      normalizeChildExtensionSources([
        " npm:foo ",
        "npm:foo",
        "javascript:bad",
        "git:github.com/example/bar",
      ]),
      ["npm:foo", "git:github.com/example/bar"],
    );
  });
});
