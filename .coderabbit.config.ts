// CodeRabbit configuration for duetto: the central frostney/coderabbit
// settings and the CodeRabbit web-UI settings (inherited), minus review of
// vendored Agent Skills.
//
// Skills listed in skills-lock.json are installed from upstream by the
// skills CLI and refreshed by .github/workflows/update-project-skills.yml;
// edits here would break their lock hashes and be overwritten, so findings
// on them belong upstream. A skill under .agents/skills that the lock does
// not list is project-authored and stays reviewed.
//
// skills-lock.yaml is a symlink to skills-lock.json: CodeRabbit's config
// sandbox imports .yaml but not .json, and JSON is valid YAML.
import { defineConfig } from "@coderabbitai/config"
import lock from "./skills-lock.yaml"

const vendoredSkills = Object.keys(
  (lock as { skills: Record<string, unknown> }).skills,
)

export default defineConfig({
  inheritance: true,
  reviews: {
    path_filters: vendoredSkills.map((name) => `!.agents/skills/${name}/**`),
  },
})
