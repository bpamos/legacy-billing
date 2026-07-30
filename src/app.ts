import express from "express";
import { billingRouter } from "./routes/billing";

export function createApp() {
  const app = express();
  app.use(express.json());
  app.use(billingRouter);
  return app;
}
