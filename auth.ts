import { PublicClientApplication, Configuration, LogLevel, BrowserCacheLocation, RedirectRequest, AuthenticationResult } from '@azure/msal-browser';
import { environment } from '../environments/environment';

export const msalConfig: Configuration = {
  auth: {
    clientId: environment.azureConfig.clientId,
    authority: environment.azureConfig.authority,
    redirectUri: environment.azureConfig.redirectUri,
    postLogoutRedirectUri: environment.azureConfig.baseUrl,
    navigateToLoginRequestUrl: true,
  },
  cache: {
    cacheLocation: BrowserCacheLocation.SessionStorage,
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) {
          return;
        }
        switch (level) {
          case LogLevel.Error:
            console.error(message);
            return;
          case LogLevel.Info:
            console.info(message);
            return;
          case LogLevel.Verbose:
            console.debug(message);
            return;
          case LogLevel.Warning:
            console.warn(message);
            return;
        }
      },
      logLevel: LogLevel.Info,
    },
  },
};

export const msalInstance = new PublicClientApplication(msalConfig);

// Helper to extract email/UPN from claims (upn has priority over preferred_username)
export function getEmailFromClaims(claims: any): string | null {
  // upn = User Principal Name (needs to be configured as optional claim in Azure AD)
  // preferred_username = default email in v2.0 tokens
  return claims?.upn || claims?.preferred_username || null;
}

// Handle redirect response after returning from Azure AD
export async function handleRedirectResponse(): Promise<AuthenticationResult | null> {
  try {
    await msalInstance.initialize();
    const response = await msalInstance.handleRedirectPromise();
    
    if (response) {
      // Log MSAL authentication claims for debugging
      const claims = response.idTokenClaims as Record<string, any>;
      console.log('[MSAL] Authentication claims:', claims);
      console.log('[MSAL] UPN:', claims?.['upn']);
      console.log('[MSAL] Preferred Username:', claims?.['preferred_username']);
      console.log('[MSAL] Name:', claims?.['name']);
      console.log('[MSAL] Account info:', response.account);
    }
    
    return response;
  } catch (error) {
    throw error;
  }
}

export async function loginWithAzure(): Promise<void> {
  try {
    await msalInstance.initialize();
    
    const loginRequest: RedirectRequest = {
      scopes: ['user.read', 'openid', 'profile'],
    };
    
    // Use redirect instead of popup - navigates in same page
    await msalInstance.loginRedirect(loginRequest);
  } catch (error) {
    throw error;
  }
}

export async function logoutAzure(): Promise<void> {
  try {
    await msalInstance.initialize();
    await msalInstance.logoutRedirect();
  } catch (error) {
    // Logout failed silently
  }
}
