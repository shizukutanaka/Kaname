// ESLint 9 flat config. Migrated from .eslintrc.json (ESLint 8):
//   env browser/es2022/node      -> globals.browser / .es2022 / .node
//   eslint:recommended           -> js.configs.recommended
//   plugin:@typescript-eslint/recommended -> tseslint.configs.recommended
//   parserOptions jsx            -> languageOptions.parserOptions.ecmaFeatures.jsx
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/",
      "node_modules/",
      "src-tauri/",
      "fuzz/",
      "**/*.config.ts",
      "**/*.config.js",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.es2022,
        ...globals.node,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "no-console": "off",
    },
  },
);
