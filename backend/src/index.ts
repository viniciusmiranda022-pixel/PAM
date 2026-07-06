import { loadConfig } from "./config.js";
import { Db } from "./db.js";
import { buildServer } from "./server.js";

const config = loadConfig();
const db = new Db(config.databaseUrl);
const app = buildServer(db, config);

app.listen({ port: config.port, host: "0.0.0.0" }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});

async function shutdown(): Promise<void> {
  await app.close();
  await db.close();
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
