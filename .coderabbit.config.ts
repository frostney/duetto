// SPIKE (never merge): shared function + the lock via a JSON import attribute.
import { defineConfig, includeRemote } from "@coderabbitai/config"
import lock from "./skills-lock.json" with { type: "json" }

const skills = includeRemote({
  path: "lib/skills.ts",
  ref: "spike/shared-functions",
}) as unknown as { vendoredSkillFilters(names: string[]): string[] }

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: skills.vendoredSkillFilters(Object.keys(lock.skills)),
  },
})
