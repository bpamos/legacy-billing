export interface PartnerClaims {
  sub: string;
  partnerId: string;
  settlementId: string;
  iat?: number;
  exp?: number;
}
