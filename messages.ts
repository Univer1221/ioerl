export const MESSAGE_TITLES = {
  AUTHENTICATION_ERROR: 'Authentication Error',
  AUTHENTICATION_FAILED: 'Authentication Failed',
  AUTHENTICATED: 'Authenticated',
  LOGIN_FAILED: 'Login Failed',
  VALIDATION_ERROR: 'Validation Error',
  ACCOUNT_CREATED: 'Account Created',
  REGISTRATION_FAILED: 'Registration Failed',
  INFO: 'Info',
  WARNING: 'Warning',
  SUCCESS: 'Success',
  ERROR: 'Error',
  SESSION_ENDED: 'Session Ended',
  UPDATED: 'Updated',
  CREATED: 'Created',
  OOPS: 'Oops...'
};

export const AUTH_MESSAGES = {
  AZURE_MISSING_EMAIL: 'No email or name found in Azure account',
  AZURE_LOGIN_SUCCESS: 'Azure Login Successful',
  AZURE_LOGIN_FAILED_DEFAULT: 'Azure login failed.',
  AZURE_LOGIN_FAILED_RETRY: 'Azure Login failed. Please try again.',
  LOGIN_SUCCESS: 'Logged in successfully',
  LOGIN_FAILED_DEFAULT: 'Login failed.',
  LOGIN_ERROR: 'An error occurred during login.'
};

export const AUTH_MESSAGE_FORMATTERS = {
  authorizedUser: (name: string) => `Authorized: ${name}`
};

export const REGISTRATION_MESSAGES = {
  EMAIL_REQUIRED: 'Email is required.',
  USERNAME_REQUIRED: 'Username is required.',
  UPN_REQUIRED: 'UPN is required.',
  PASSWORD_MISMATCH: 'Passwords do not match.',
  PASSWORD_REQUIRED: 'Password is required.',
  REGISTRATION_SUCCESS:
    'Registration successful! Your account is pending approval. You will be notified once approved. Please check your email for further instructions.',
  REGISTRATION_FAILED: 'Registration failed.',
  REGISTRATION_ERROR: 'An error occurred during registration.'
};

export const EMAIL_MESSAGES = {
  TP_SERVICES_DETECTED: 'TP Internal app detected - SMTP relay is automatically managed, no password required',
  REQUIRED_FIELDS: 'Application, SMTP User Email, Subject and To Recipients are required',
  APP_PASSWORD_REQUIRED: 'App Password is required for External SMTP',
  TEST_EMAIL_SUCCESS: 'Test Email sent successfully',
  GUIDANCE_MISSING_CREDENTIALS:
    'Could not send guidance email - missing credentials. This only works for newly created applications.',
  GUIDANCE_SUCCESS: 'Guidance email sent successfully',
  GUIDANCE_FAILED: 'Failed to send guidance email',
  SEND_EMAIL_ERROR: 'An error occurred while sending email',
  EXPORT_EMPTY: 'No emails to export',
  EXPORT_SUCCESS: 'Emails exported successfully',
  CSV_HEADERS: ['Owner', 'UPN', 'Application', 'Sender', 'Subject', 'Body', 'Service', 'Date', 'Time', 'Status'],
  CSV_STATUS_DELIVERED: 'Delivered',
  CSV_STATUS_FAILED: 'Failed'
};

export const APPLICATION_MESSAGES = {
  LOAD_ERROR: 'Could not load application data',
  UPDATE_ERROR: 'An error occurred while updating',
  SAVE_ERROR: 'An error occurred while saving'
};

export const APPLICATION_MESSAGE_FORMATTERS = {
  updateSuccess: (name: string) => `${name} updated successfully`,
  saveSuccess: (name: string) => `${name} saved successfully`
};

export const APPLICATION_LABELS = {
  SMTP_PROVIDERS: [
    { value: 'External', label: 'External SMTP' },
    { value: 'TPInternal', label: 'TP Internal' }
  ]
};

export const EMAIL_LOOKUP_MESSAGES = {
  LOAD_ERROR: 'Could not load email service data',
  UPDATE_ERROR: 'An error occurred while updating',
  SAVE_ERROR: 'An error occurred while saving'
};

export const EMAIL_LOOKUP_MESSAGE_FORMATTERS = {
  updateSuccess: (serviceName: string) => `${serviceName} updated successfully`,
  saveSuccess: (serviceName: string) => `${serviceName} saved successfully`
};

export const DASHBOARD_MESSAGES = {
  LOAD_ERROR: 'Failed to load dashboard data. Please check if the API is running and accessible.'
};

export const DASHBOARD_LABELS = {
  BAR_LABEL_SENT_EMAIL: 'No. of Sent Email',
  BAR_LABEL_NO_DATA: 'No Data',
  ALL_APPLICATIONS: 'ALL'
};

export const ADMIN_REGISTRATION_MESSAGES = {
  REGISTRATION_SUCCESS: (email: string) => `Registration for ${email} is successful.`,
  REGISTRATION_ERROR: 'An error occurred'
};

export const APPLICATION_APPROVAL_MESSAGES = {
  APPLICATION_VERIFIED: 'Application has been verified',
  APPROVAL_ERROR: 'An error occurred'
};

export const USER_MESSAGES = {
  ID_VERIFIED: 'ID has been verified'
};

export const PASSWORD_MESSAGES = {
  PASSWORD_MISMATCH: 'Passwords do not match',
  PASSWORD_UPDATE_SUCCESS: 'Password updated successfully',
  PASSWORD_UPDATE_ERROR: 'An error occurred while updating password'
};

export const ERROR_MESSAGES = {
  UNKNOWN_ERROR: 'An unknown error occurred!',
  SOMETHING_WENT_WRONG: 'Something went wrong. Please try again later.',
  SESSION_EXPIRED: 'Session expired. Please login again.',
  FORBIDDEN: 'You do not have permission to perform this action.',
  SERVER_UNKNOWN: 'An unknown server error occurred',
  CLIENT_ERROR: (message: string) => `Error: ${message}`
};

export const SESSION_MESSAGES = {
  LOGOUT_SUCCESS: 'Logged out successfully'
};

export const COMMON_MESSAGES = {
  ALL_LABEL: 'ALL',
  GENERIC_ERROR: 'An error occurred'
};
