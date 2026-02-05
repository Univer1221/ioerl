import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, from, of } from 'rxjs';
import { map, mergeMap } from 'rxjs/operators';
import { BaseService } from './api';
import { SecureStorageService } from './secure-storage.service';
import { ApiResponse, ResultCodes } from '../models/api-response.model';
import { logoutAzure } from '../auth';

// Role IDs matching backend RoleType enum
export enum RoleId {
  UNKNOWN = 0,
  MODERATOR = 1,
  USER = 2,
  ADMIN = 3,
  TESTER = 4
}

type SessionCache = {
  token: string | null;
  role: string | null;
  roleId: number | null;
  email: string | null;
  userId: string | null;
};

@Injectable({
  providedIn: 'root',
})
export class AuthService extends BaseService {
  private router = inject(Router);
  private secureStorage = inject(SecureStorageService);
  private cache: SessionCache = { token: null, role: null, roleId: null, email: null, userId: null };
  private ready: Promise<void> | null = null;
  private initialized = false;

  constructor() {
    super();
    // Don't start async operations in constructor - defer to initializeSession
  }

  async initializeSession(): Promise<void> {
    // Prevent multiple initializations
    if (this.initialized) {
      return;
    }
    this.initialized = true;
    
    // Quick check: if there's no session data at all, return immediately
    const hasEncryptedData = Object.keys(sessionStorage).some(k => k.startsWith('__encrypted_'));
    const hasLegacyData = sessionStorage.getItem('Auth') !== null;
    
    if (!hasEncryptedData && !hasLegacyData) {
      // No session data, no need to wait for restoration
      return;
    }
    
    // Only restore if there's data
    this.ready = this.restoreFromStorage();
    
    const timeout = new Promise<void>((resolve) => {
      setTimeout(() => {
        console.warn('AuthService: Session restoration timed out, proceeding without cached session');
        resolve();
      }, 3000);
    });
    
    await Promise.race([this.ready, timeout]);
  }

  login(credentials: any): Observable<any> {
    return this.post<ApiResponse<string>>('AppUser/AppUserAuthentication', credentials).pipe(
      mergeMap((response: ApiResponse<string>) => {
        // Check resultCode instead of status
        if (response && response.resultCode === ResultCodes.SUCCESS) {
          // Extract token from resultData array
          const token = response.resultData && response.resultData.length > 0 ? response.resultData[0] : null;
          if (token) {
            return from(this.setSession(token)).pipe(map(() => {
              return response;
            }));
          }
        }
        return of(response);
      })
    );
  }

  azureLogin(email: string, upn: string, displayName?: string, username?: string): Observable<any> {
    return this.post<ApiResponse<string>>('AppUser/azure-authenticate', { 
      Email: email,
      Upn: upn,
      DisplayName: displayName,
      Username: username
    }).pipe(
      mergeMap((response: ApiResponse<string>) => {
        // Check resultCode instead of status
        if (response && response.resultCode === ResultCodes.SUCCESS) {
          // Extract token from resultData array
          const token = response.resultData && response.resultData.length > 0 ? response.resultData[0] : null;
          if (token) {
            return from(this.setSession(token)).pipe(map(() => response));
          }
        }
        return of(response);
      })
    );
  }

  private async restoreFromStorage(): Promise<void> {
    try {
      // Quick check: if there's nothing in storage, skip the async crypto operations
      const hasEncryptedData = Object.keys(sessionStorage).some(k => k.startsWith('__encrypted_'));
      const hasLegacyData = sessionStorage.getItem('Auth') !== null;
      
      if (!hasEncryptedData && !hasLegacyData) {
        // No session data to restore, exit early
        return;
      }

      // Try to restore encrypted claims and token from sessionStorage
      const role = await this.secureStorage.getItem<string>('Role', true);
      const email = await this.secureStorage.getItem<string>('LoginEmail', true);
      const userId = await this.secureStorage.getItem<string>('UserId', true);
      const token = await this.secureStorage.getItem<string>('Auth', true);

      if (token) {
        await this.cacheFromToken(token);
      }

      if (role || email || userId) {
        this.cache.role = role || this.cache.role;
        this.cache.email = email || this.cache.email;
        this.cache.userId = userId || this.cache.userId;
        return;
      }

      // Migration: check for legacy unencrypted token
      const legacyToken = sessionStorage.getItem('Auth');
      if (legacyToken) {
        await this.cacheFromToken(legacyToken);
        // Store claims encrypted, clean up legacy unencrypted storage
        await Promise.all([
          this.secureStorage.setItem('Role', this.cache.role, true),
          this.secureStorage.setItem('LoginEmail', this.cache.email, true),
          this.secureStorage.setItem('UserId', this.cache.userId, true)
        ]);
        sessionStorage.removeItem('Auth');
        sessionStorage.removeItem('Role');
        sessionStorage.removeItem('LoginEmail');
        sessionStorage.removeItem('UserId');
      }
    } catch (error) {
      this.cache = { token: null, role: null, roleId: null, email: null, userId: null };
    }
  }

  private async setSession(token: string): Promise<void> {
    try {
      await this.cacheFromToken(token);
      
      // Use plain sessionStorage for now to avoid crypto issues
      sessionStorage.setItem('Auth', token);
      sessionStorage.setItem('Role', this.cache.role || '');
      sessionStorage.setItem('RoleId', this.cache.roleId?.toString() || '');
      sessionStorage.setItem('LoginEmail', this.cache.email || '');
      sessionStorage.setItem('UserId', this.cache.userId || '');
    } catch (error) {
      // Continue anyway - the cache is already populated
    }
  }

  private async cacheFromToken(token: string): Promise<void> {
    try {
      // Ensure token is a valid JWT format (contains exactly 2 dots)
      const parts = token.split('.');
      if (parts.length !== 3) {
        this.cache = { token: null, role: null, roleId: null, email: null, userId: null };
        return;
      }

      // Validate token expiration - but don't logout during login flow
      if (!this.isTokenValid(token)) {
        this.cache = { token: null, role: null, roleId: null, email: null, userId: null };
        return;
      }

      this.cache.token = token;
      const payload = JSON.parse(atob(parts[1]));
      const role = payload['role'] || payload['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
      const roleIdStr = payload['roleId'];
      this.cache.role = role;
      this.cache.roleId = roleIdStr ? parseInt(roleIdStr, 10) : null;
      this.cache.email = payload['unique_name'] || payload['name'];
      this.cache.userId = payload['nameid'] || payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'];
    } catch (error) {
      this.cache = { token: null, role: null, roleId: null, email: null, userId: null };
    }
  }

  private isTokenValid(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return false;
      }

      const payload = JSON.parse(atob(parts[1]));
      const exp = payload['exp'];

      if (!exp) {
        // No expiration claim, consider it valid
        return true;
      }

      // Check if token has expired (exp is in seconds, Date.now() is in milliseconds)
      const currentTime = Math.floor(Date.now() / 1000);
      return exp > currentTime;
    } catch (error) {
      return false;
    }
  }

  async updateLoginEmail(email: string): Promise<void> {
    this.cache.email = email;
    await this.secureStorage.setItem('LoginEmail', email, true);
  }

  register(userData: any): Observable<any> {
    return this.post<ApiResponse<string>>('AppUser/AppUserRegistration', userData);
  }

  async logout(): Promise<void> {
    // Clear in-memory cache
    this.cache = { token: null, role: null, roleId: null, email: null, userId: null };
    
    // Clear all sessionStorage (including encrypted items)
    sessionStorage.clear();
    
    // Clear all localStorage (including encrypted items)
    localStorage.clear();
    
    // Clear any caches (Cache API)
    if ('caches' in window) {
      try {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(name => caches.delete(name)));
      } catch (e) {
        // Cache clearing failed, continue with logout
      }
    }
    
    // Perform Azure AD logout (this will redirect to Azure logout page)
    await logoutAzure();
  }

  async isAuthenticated(): Promise<boolean> {
    // Return from cache immediately if available
    if (this.cache.token) {
      return true;
    }
    // Try plain sessionStorage
    const token = sessionStorage.getItem('Auth');
    if (token) {
      await this.cacheFromToken(token);
      return true;
    }
    return false;
  }

  async getRole(): Promise<string | null> {
    // Return from cache immediately if available (e.g., after login)
    if (this.cache.role) {
      return this.cache.role;
    }
    // Try plain sessionStorage
    const storedRole = sessionStorage.getItem('Role');
    if (storedRole) {
      this.cache.role = storedRole;
      return storedRole;
    }
    return null;
  }

  async getRoleId(): Promise<number | null> {
    // Return from cache immediately if available
    if (this.cache.roleId !== null) {
      return this.cache.roleId;
    }
    // Try plain sessionStorage
    const storedRoleId = sessionStorage.getItem('RoleId');
    if (storedRoleId) {
      this.cache.roleId = parseInt(storedRoleId, 10);
      return this.cache.roleId;
    }
    return null;
  }

  /**
   * Check if user is admin using roleId first, fallback to case-insensitive string comparison
   */
  async isAdmin(): Promise<boolean> {
    try {
      // First try by roleId (more reliable)
      const roleId = await this.getRoleId();
      if (roleId !== null) {
        return roleId === RoleId.ADMIN;
      }
      
      // Fallback to case-insensitive string comparison
      const role = await this.getRole();
      return role?.toUpperCase() === 'ADMIN';
    } catch (error) {
      // Last resort fallback
      const role = await this.getRole();
      return role?.toUpperCase() === 'ADMIN';
    }
  }

  async getEmail(): Promise<string | null> {
    // Return from cache immediately if available
    if (this.cache.email) {
      return this.cache.email;
    }
    // Try plain sessionStorage
    const storedEmail = sessionStorage.getItem('LoginEmail');
    if (storedEmail) {
      this.cache.email = storedEmail;
      return storedEmail;
    }
    return null;
  }

  async getUserId(): Promise<string | null> {
    // Return from cache immediately if available
    if (this.cache.userId) {
      return this.cache.userId;
    }
    // Try plain sessionStorage
    const storedUserId = sessionStorage.getItem('UserId');
    if (storedUserId) {
      this.cache.userId = storedUserId;
      return storedUserId;
    }
    return null;
  }

  getUserInfo(): Observable<ApiResponse<any>> {
    return this.get<ApiResponse<any>>('AppUser/GetUserInfo');
  }

  // Synchronous getter for token from cache (used by interceptor)
  // Returns null if no token in cache (e.g., on page refresh)
  getTokenFromCache(): string | null {
    if (!this.cache.token) {
      this.cache.token = sessionStorage.getItem('Auth');
    }
    return this.cache.token;
  }
}
