import express from "express";
import cors from "cors";
import helmet from "helmet";
import { config } from "./config";
import authRoutes from "./routes/auth";
import scanRoutes from "./routes/scans";
import { errorHandler, notFound } from "./middleware/errorHandler";

export const app = express();

app.use(helmet());
app.use(cors({ origin: config.frontendOrigin })); // SEC-6: only the known frontend
app.use(express.json({ limit: "100kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", mlMode: config.mlMode });
});

app.use("/api/auth", authRoutes);
app.use("/api/scans", scanRoutes);

app.use(notFound);
app.use(errorHandler);
