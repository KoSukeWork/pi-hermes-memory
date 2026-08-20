import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { installDeferred } from "./lazy-extension.js";

export default function (pi: ExtensionAPI) {
	installDeferred(pi, () => import("./index.js"), {
		commands: [
			{ name: "memory-insights", description: "Show Hermes memory insights" },
			{ name: "memory-skills", description: "List procedural memory skills" },
			{ name: "memory-consolidate", description: "Consolidate Hermes memory" },
			{ name: "memory-interview", description: "Interview to pre-fill user profile" },
			{ name: "memory-switch-project", description: "Switch or list project memories" },
			{ name: "memory-index-sessions", description: "Index Pi sessions into memory search" },
			{ name: "learn-memory-tool", description: "Learn how the memory tools work" },
			{ name: "memory-preview-context", description: "Preview memory context that would be injected" },
			{
				name: "memory-pin",
				description: "Pin standing memory instructions",
				completions: ["list", "remove", "clear"],
			},
			{ name: "memory-sync-markdown", description: "Sync markdown memories into SQLite" },
		],
	});
}
