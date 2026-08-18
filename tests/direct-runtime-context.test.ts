import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  clearDirectRuntimeContext,
  getDirectRuntimeContext,
  rememberDirectRuntimeContext,
} from "../src/direct-runtime-context.js";

describe("direct runtime context", () => {
  beforeEach(() => {
    clearDirectRuntimeContext();
  });

  it("ignores contexts without a model registry", () => {
    rememberDirectRuntimeContext(undefined);
    rememberDirectRuntimeContext({});
    rememberDirectRuntimeContext({ model: { provider: "newapi", id: "x" } });
    assert.equal(getDirectRuntimeContext(), null);
  });

  it("remembers the live model and registry for overflow consolidation", () => {
    const modelRegistry = { getAvailable: () => [] };
    const model = { provider: "my_gateway", id: "claude-sonnet-4-5" };
    rememberDirectRuntimeContext({ model, modelRegistry, extra: true });

    assert.deepStrictEqual(getDirectRuntimeContext(), { model, modelRegistry });
  });

  it("replaces the remembered context when the session model changes", () => {
    const first = { getAvailable: () => ["old"] };
    const second = { getAvailable: () => ["new"] };
    rememberDirectRuntimeContext({ modelRegistry: first });
    rememberDirectRuntimeContext({
      model: { provider: "my_gateway", id: "gpt-4o" },
      modelRegistry: second,
    });

    assert.equal(getDirectRuntimeContext()?.modelRegistry, second);
    assert.equal(getDirectRuntimeContext()?.model?.id, "gpt-4o");
  });
});
