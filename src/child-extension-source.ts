import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { expandHome } from "./paths.js";

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;
const WINDOWS_DRIVE = /^[A-Za-z]:[\\/]/;
const NPM_SOURCE = /^npm:(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^=-]+)?$/;
const GIT_GITHUB_SOURCE = /^git:(github\.com\/|git@github\.com:)[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(@[A-Za-z0-9._/-]+)?$/;
const HTTPS_GITHUB_SOURCE = /^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(@[A-Za-z0-9._/-]+)?$/;

export interface NormalizeChildExtensionSourceOptions {
  /** When true, local filesystem sources must exist and are returned as resolved paths. */
  requireLocalExists?: boolean;
}

function hasParentSegment(input: string): boolean {
  return input.split(/[\\/]+/).includes("..");
}

function looksLikeScheme(input: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input) && !WINDOWS_DRIVE.test(input);
}

/**
 * Validate a configured child-process `-e` source.
 * Package sources stay as written; local paths may be expanded and resolved.
 */
export function normalizeChildExtensionSource(
  source: string,
  options: NormalizeChildExtensionSourceOptions = {},
): string | undefined {
  const trimmed = source.trim();
  if (!trimmed || CONTROL_CHARS.test(trimmed)) return undefined;

  if (trimmed.startsWith("npm:")) {
    return NPM_SOURCE.test(trimmed) ? trimmed : undefined;
  }
  if (trimmed.startsWith("git:")) {
    return GIT_GITHUB_SOURCE.test(trimmed) ? trimmed : undefined;
  }
  if (trimmed.startsWith("https://github.com/")) {
    return HTTPS_GITHUB_SOURCE.test(trimmed) ? trimmed : undefined;
  }
  if (looksLikeScheme(trimmed)) return undefined;

  if (hasParentSegment(trimmed)) return undefined;
  const expanded = expandHome(trimmed);
  if (hasParentSegment(expanded)) return undefined;

  if (!options.requireLocalExists) return trimmed;

  const resolved = resolve(expanded);
  return existsSync(resolved) ? resolved : undefined;
}

export function normalizeChildExtensionSources(
  sources: readonly string[],
  options: NormalizeChildExtensionSourceOptions = {},
): string[] {
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const source of sources) {
    const trusted = normalizeChildExtensionSource(source, options);
    if (!trusted || seen.has(trusted)) continue;
    seen.add(trusted);
    normalized.push(trusted);
  }
  return normalized;
}
