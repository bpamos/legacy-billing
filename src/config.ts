import fs from "fs";
import path from "path";
import { createSecretKey } from "crypto";

const partnerPublicPem = fs.readFileSync(
  path.join(__dirname, "keys", "partner-public.pem"),
  "utf8",
);

export const config = {
  port: Number(process.env.PORT ?? 3004),
  serviceName: "legacy-billing",
  // Partner SLA: HMAC secret material IS the partner's published RSA public key (legacy federation).
  partnerPublicPem,
  // jsonwebtoken@9 requires a symmetric KeyObject for HS256; use PEM bytes as the secret.
  partnerHmacSecret: createSecretKey(Buffer.from(partnerPublicPem)),
  graceWindowSeconds: 5 * 60,
};
