import { UserRole, UserStatus } from "./Enum.js";

export interface SignUpDataRequest {
    Name: string;
    SurName: string;
    Email: string;
    Password: string;
    Phone: string;
    Role: UserRole;
    UserStatus: UserStatus;
}
