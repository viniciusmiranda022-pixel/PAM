import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["integration/**/*.test.ts", "security/**/*.test.ts"],
    // Suites compartilham um Postgres real: sem paralelismo entre arquivos para
    // evitar corrida no reset de dados.
    fileParallelism: false,
    hookTimeout: 30_000,
    testTimeout: 30_000,
  },
});
