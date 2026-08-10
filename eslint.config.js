// Flat ESLint config for the monorepo. Kept intentionally light; the probe
// safety rules live in @perimeter/probe-linter (spec §3.4), not here.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/*.tsbuildinfo"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        // A single lint-only project covering src + tests + templates + root
        // config, so type-aware rules find every linted file (test files are
        // excluded from the build tsconfigs, hence a dedicated project here).
        project: ["./tsconfig.eslint.json"],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
  {
    // The reference target is deliberately vulnerable; relax a couple of rules.
    files: ["apps/reference-target/**/*.ts"],
    rules: { "no-console": "off" },
  },
  {
    // Probe scaffolding templates carry intentional placeholders (unused ctx, TODOs).
    files: ["**/templates/**/*.ts"],
    rules: { "@typescript-eslint/no-unused-vars": "off" },
  },
);
