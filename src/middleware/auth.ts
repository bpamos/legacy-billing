import type { Request, Response, NextFunction } from "express";
import { verifyPartnerToken } from "../partner";
import type { PartnerClaims } from "../types";

export interface AuthedRequest extends Request {
  partner?: PartnerClaims;
}

export function requirePartner(req: AuthedRequest, res: Response, next: NextFunction): void {
  const header = req.header("authorization");
  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({ error: "missing_bearer_token" });
    return;
  }
  try {
    req.partner = verifyPartnerToken(header.slice("Bearer ".length).trim());
    next();
  } catch {
    res.status(401).json({ error: "invalid_partner_token" });
  }
}
