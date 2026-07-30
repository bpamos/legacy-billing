import jwt from "jsonwebtoken";
import { config } from "./config";
import type { PartnerClaims } from "./types";

/**
 * Verifies a partner settlement token per the legacy federation rules:
 * HS256 using the partner's published RSA public key PEM *string* as the HMAC
 * secret, with a clockTolerance grace window for recently-expired tokens.
 * BILL-204 forbids KeyObject/Buffer derivations of that PEM (see tests).
 */
export function verifyPartnerToken(token: string): PartnerClaims {
  return jwt.verify(token, config.partnerPublicPem, {
    algorithms: ["HS256"],
    clockTolerance: config.graceWindowSeconds,
  }) as PartnerClaims;
}
