// SPIKE (never merge) control: same shape, no JSON import.
import { defineConfig } from "@coderabbitai/config"

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: ["!.agents/skills/code-review/**"],
  },
})
