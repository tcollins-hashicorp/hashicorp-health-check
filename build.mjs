import { build } from "esbuild";
import { mkdirSync, copyFileSync, rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/assets", { recursive: true });

await build({
  entryPoints: ["src/main.jsx"],
  bundle: true,
  minify: true,
  sourcemap: false,
  format: "iife",
  target: ["es2019"],
  jsx: "automatic",
  loader: { ".jsx": "jsx" },
  define: { "process.env.NODE_ENV": '"production"' },
  outfile: "dist/assets/app.js",
});

copyFileSync("public/index.html", "dist/index.html");
console.log("Built dist/ (self-contained, no external dependencies).");
