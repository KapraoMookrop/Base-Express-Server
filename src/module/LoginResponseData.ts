import { UserRole, UserStatus } from "./Enum.js";

export interface LoginResponseData {
    Name: string;
    SurName: string;
    Email: string;
    Phone: string;
    Role: UserRole;
    UserStatus: UserStatus;
    JWT: string;
    IsEnabled2FA: boolean;
}
