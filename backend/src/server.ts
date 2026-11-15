import { app } from "./app";
import { config } from "./config";
import { prisma } from "./db";

async function main() {
  await prisma.$connect();
  app.listen(config.port, () => {
    console.log(`CipherGuard backend running on http://localhost:${config.port}  (ML mode: ${config.mlMode})`);
  });
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
