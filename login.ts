import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth';
import { loginWithAzure, handleRedirectResponse } from '../../auth';
import { ToastrService } from 'ngx-toastr';
import { IMAGE_PATHS } from '../../shared/constants/image-paths';
import { ResultCodes } from '../../models/api-response.model';
import { AUTH_MESSAGE_FORMATTERS, AUTH_MESSAGES, MESSAGE_TITLES } from '../../shared/constants/messages';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './login.html',
  styleUrl: './login.scss'
})
export class LoginComponent implements OnInit {
  public readonly IMAGE_PATHS = IMAGE_PATHS;
  private authService = inject(AuthService);
  private router = inject(Router);
  private toastr = inject(ToastrService);

  userLogin = {
    Email: '',
    Password: ''
  };
  errorMessage = '';

  async ngOnInit() {
    // Handle redirect response after returning from Azure AD
    try {
      const response = await handleRedirectResponse();
      if (response && response.account) {
        this.processAzureLogin(response);
      }
    } catch (error) {
      this.toastr.error(AUTH_MESSAGES.AZURE_LOGIN_FAILED_RETRY, MESSAGE_TITLES.AUTHENTICATION_ERROR);
    }
  }

  private processAzureLogin(response: any) {
    // Extract claims from idTokenClaims
    const claims = response.idTokenClaims || {};
    
    console.log('[Azure Login] All claims:', claims);
    console.log('[Azure Login] Account:', response.account);
    
    // For external/guest users, the email might be in different places:
    // 1. 'email' claim - the actual email address
    // 2. 'upn' claim - User Principal Name (may have #ext# format for guests)
    // 3. 'preferred_username' - may also have #ext# format
    // Priority: email > upn (if not #ext# format) > extract from preferred_username
    
    let email = claims['email'];
    let upn = claims['upn'] || claims['preferred_username'] || response.account.username;
    
    // If email claim not available, try to extract real email from external user format
    // External format: user_domain.com#ext#@tenant.onmicrosoft.com
    if (!email && upn && upn.includes('#ext#')) {
      // Extract original email: astrafluxdynamics_gmail.com#ext#@... -> astrafluxdynamics@gmail.com
      const extPart = upn.split('#ext#')[0]; // astrafluxdynamics_gmail.com
      // Replace last underscore with @ to get email
      const lastUnderscoreIdx = extPart.lastIndexOf('_');
      if (lastUnderscoreIdx > 0) {
        email = extPart.substring(0, lastUnderscoreIdx) + '@' + extPart.substring(lastUnderscoreIdx + 1);
      }
    }
    
    // If still no email, use UPN as-is
    if (!email) {
      email = upn;
    }
    
    // Display Name - human readable name
    const displayName = claims['name'] || response.account.name || email.split('@')[0];
    
    // Username - extract from email (part before @)
    const username = email.split('@')[0];
    
    console.log('[Azure Login] Extracted Email:', email);
    console.log('[Azure Login] UPN:', upn);
    console.log('[Azure Login] DisplayName:', displayName);
    console.log('[Azure Login] Username:', username);
    
    if (!upn) {
      this.toastr.error(AUTH_MESSAGES.AZURE_MISSING_EMAIL, MESSAGE_TITLES.AUTHENTICATION_ERROR);
      return;
    }
    
    // Send to backend: Email = actual email (or UPN if no email), Upn = UPN, DisplayName = full name, Username = short name
    this.authService.azureLogin(email, upn, displayName, username).subscribe({
      next: async (res) => {
        if (res && res.resultCode === ResultCodes.SUCCESS) {
          this.toastr.success(
            AUTH_MESSAGES.AZURE_LOGIN_SUCCESS,
            AUTH_MESSAGE_FORMATTERS.authorizedUser(displayName)
          );
          // Navigate to common dashboard for all roles
          this.router.navigate(['/Dashboard']);
        } else {
          const message = res.resultMessages && res.resultMessages.length > 0 
            ? res.resultMessages[0] 
            : AUTH_MESSAGES.AZURE_LOGIN_FAILED_DEFAULT;
          this.toastr.error(message, MESSAGE_TITLES.AUTHENTICATION_FAILED);
          
          if (res.resultCode === ResultCodes.USER_NOT_APPROVED) {
            this.router.navigate(['/NoAccess']);
          }
        }
      },
      error: (err) => {
        this.toastr.error(AUTH_MESSAGES.AZURE_LOGIN_FAILED_RETRY, MESSAGE_TITLES.AUTHENTICATION_ERROR);
      }
    });
  }

  async onAzureLogin() {
    try {
      // This will redirect to Azure AD in the same page
      await loginWithAzure();
    } catch (error) {
      this.toastr.error(AUTH_MESSAGES.AZURE_LOGIN_FAILED_RETRY, MESSAGE_TITLES.AUTHENTICATION_ERROR);
    }
  }

  onSubmit(event: Event) {
    event.preventDefault();
    this.authService.login(this.userLogin).subscribe({
      next: async (response) => {
        if (response && response.resultCode === ResultCodes.SUCCESS) {
          this.toastr.success(AUTH_MESSAGES.LOGIN_SUCCESS, MESSAGE_TITLES.AUTHENTICATED);
          const isAdmin = await this.authService.isAdmin();
          // Navigate to common dashboard for all roles
          this.router.navigate(['/Dashboard']);
        } else {
          // Handle business logic failures using resultCode and resultMessages
          const message = response.resultMessages && response.resultMessages.length > 0 
            ? response.resultMessages[0] 
            : AUTH_MESSAGES.LOGIN_FAILED_DEFAULT;
          this.errorMessage = message;
          this.toastr.error(message, MESSAGE_TITLES.LOGIN_FAILED);
          
          // Special handling for unapproved users
          if (response.resultCode === ResultCodes.USER_NOT_APPROVED) {
            this.router.navigate(['/NoAccess']);
          }
          
          // Special handling for Azure AD users trying to use password login
          if (response.resultCode === ResultCodes.AZURE_AD_LOGIN_REQUIRED) {
            this.toastr.info('Please use the "Login with Azure AD" button below.', 'Azure AD Account');
          }
        }
      },
      error: (err) => {
        this.errorMessage = err.error?.detail || err.error?.message || err.message || AUTH_MESSAGES.LOGIN_ERROR;
        this.toastr.error(this.errorMessage, MESSAGE_TITLES.LOGIN_FAILED);
      }
    });
  }
}