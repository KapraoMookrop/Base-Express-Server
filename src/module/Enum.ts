//  Role ของผู้ใช้ในระบบ
export enum UserRole {
  ADMIN = "Admin",
}

// สถานะบัญชีผู้ใช้
export enum UserStatus {
  ACTIVE = "Active",
  PENDING_VERIFICATION = "Pending",
  INACTIVE = "InActive",
}

// ประเภทของการยืนยัน 2FA
export enum Verify2FAType {
  VERIFYLOGIN = "VERIFYLOGIN",
  VERIFYENABLE = "VERIFYENABLE",
}