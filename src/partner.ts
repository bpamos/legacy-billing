import jwt from "jsonwebtoken";
import { config } from "./config";
import type { PartnerClaims } from "./types";

/**
 * Verifies a partner settlement token per the legacy federation rules:
 * HS256 using the partner's published RSA public key as the HMAC secret,
 * with a clockTolerance grace window for recently-expired tokens.
 */
export function verifyPartnerToken(token: string): PartnerClaims {
  return jwt.verify(token, config.partnerHmacSecret, {
    algorithms: ["HS256"],
    clockTolerance: config.graceWindowSeconds,
  }) as PartnerClaims;
}
