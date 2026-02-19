import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";

export default defineConfig(
    [
        globalIgnores(["public/**"]),
        js.configs.recommended,
        {
            files: ["**/*.js"],
            languageOptions: {
                globals: { ...globals.node, },
                ecmaVersion: "latest",
                sourceType: "module",
            },
            rules: {
                "no-unused-vars": ["error", { args: "none" }],
            },
        }
    ]
);
