// SPIKE (never merge): call a function shared from frostney/coderabbit.
import { defineConfig, includeRemote } from "@coderabbitai/config"

const skills = includeRemote({
  path: "lib/skills.ts",
  ref: "spike/shared-functions",
}) as unknown as { vendoredSkillFilters(names: string[]): string[] }

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: skills.vendoredSkillFilters(["code-review", "deliver"]),
  },
})
