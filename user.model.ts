export interface User {
  userId: string;
  username: string;
  email: string;
  upn?: string;
  roles: UserRole[];
  active: number;
  createdDateTime?: string;
  profileImageBase64?: string;
}

export interface UserRole {
  roleId: string;
  roleName: string;
}

export interface Role {
  id: number;
  name: string;
  description?: string;
  active?: number;
  roleId: string;
  roleName: string;
}
