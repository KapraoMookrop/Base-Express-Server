import { UserRole, UserStatus } from "./Enum.js";

export interface LoginResponseData {
    FullName: string;
    Email: string;
    Phone: string;
    Role: UserRole;
    UserStatus: UserStatus;
    JWT: string;
    IsEnabled2FA: boolean;
}
