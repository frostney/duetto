// SPIKE (never merge): read the lock through a .yaml symlink (JSON is YAML).
import { defineConfig } from "@coderabbitai/config"
import lock from "./skills-lock.yaml"

const vendored = Object.keys((lock as { skills: Record<string, unknown> }).skills)

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: vendored.map((name) => `!.agents/skills/${name}/**`),
  },
})
