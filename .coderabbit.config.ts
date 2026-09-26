// SPIKE (never merge): can a repository config derive path filters from
// skills-lock.json? Vendored skills (listed in the lock) are excluded from
// review; project-authored skills under .agents/skills stay reviewed.
import { defineConfig } from "@coderabbitai/config"
import lock from "./skills-lock.json"

const vendored = Object.keys((lock as { skills: Record<string, unknown> }).skills)

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: vendored.map((name) => `!.agents/skills/${name}/**`),
  },
})
