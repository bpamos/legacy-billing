import fs from "fs";
import path from "path";

export const config = {
  port: Number(process.env.PORT ?? 3004),
  serviceName: "legacy-billing",
  // Partner SLA: HMAC secret material IS the partner's published RSA public key (legacy federation).
  partnerPublicPem: fs.readFileSync(path.join(__dirname, "keys", "partner-public.pem"), "utf8"),
  graceWindowSeconds: 5 * 60,
};
