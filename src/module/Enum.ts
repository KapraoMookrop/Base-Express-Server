//  Role ของผู้ใช้ในระบบ
export enum UserRole {
  BUYER = "BUYER",
  SELLER = "SELLER",
  ADMIN = "ADMIN",
}

// สถานะบัญชีผู้ใช้
export enum UserStatus {
  ACTIVE = "ACTIVE",
  PENDING_VERIFICATION = "PENDING_VERIFICATION",
  SUSPENDED = "SUSPENDED",
}

// ประเภทของการยืนยัน 2FA
export enum Verify2FAType {
  VERIFYLOGIN = "VERIFYLOGIN",
  VERIFYENABLE = "VERIFYENABLE",
}