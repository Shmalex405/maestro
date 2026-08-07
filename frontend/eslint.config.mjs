import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Tauri build outputs — generated Rust/JS artifacts, not source. Without
    // this, eslint scans src-tauri/target/**/tauri-codegen-assets/*.js and
    // reports thousands of false positives on machine-generated code.
    "src-tauri/target/**",
    "src-tauri/gen/**",
  ]),
]);

export default eslintConfig;
