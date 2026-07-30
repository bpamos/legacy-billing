import { Router } from "express";
import { requirePartner, type AuthedRequest } from "../middleware/auth";
import { verifyPartnerToken } from "../partner";

export const billingRouter = Router();

billingRouter.get("/health", (_req, res) => {
  res.json({ ok: true, service: "legacy-billing" });
});

billingRouter.post("/settlement/accept", requirePartner, (req: AuthedRequest, res) => {
  res.status(202).json({
    accepted: true,
    settlementId: req.partner?.settlementId,
    partnerId: req.partner?.partnerId,
  });
});

billingRouter.post("/settlement/inspect", (req, res) => {
  try {
    const claims = verifyPartnerToken(String(req.body?.token ?? ""));
    res.json({ ok: true, claims });
  } catch {
    res.status(401).json({ ok: false });
  }
});
