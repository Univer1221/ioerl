using System.ComponentModel.DataAnnotations;

namespace TPEmail.BusinessModels.RequestModels
{
    public class AppUserPostDto
    {
        public Guid Id { get; set; }

        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        [Display(Name = "UPN")]
        public string Upn { get; set; } = string.Empty;

        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string AppSecret { get; set; } = string.Empty;

        [Display(Name = "Confirm Password")]
        [Compare("AppSecret")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;
        public int? RoleId { get; set; }
        public int Active { get; set; }
    }

    public class AppUserCredentialsUpdateDto
    {
        public Guid UserId { get; set; }

        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [StringLength(maximumLength: 100, MinimumLength = 4)]
        public string AppSecret { get; set; } = string.Empty;

        [Compare("AppSecret")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;
        public string ModifiedBy { get; set; } = string.Empty;
        public DateTime ModificationDateTime { get; set; }

        public int? RoleId { get; set; }
    }

    public class AppUserGetDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string? Upn { get; set; }
        public string? AppSecret { get; set; }  // Null for Azure AD users
        public string? Salt { get; set; }  // Null for Azure AD users
        public string? EncryptionKey { get; set; }  // Null for Azure AD users
        public int Active { get; set; }
        public IList<AppUserRoleDto> Roles { get; set; } = new List<AppUserRoleDto>();
        public IList<ApplicationGetDto> Applications { get; set; } = new List<ApplicationGetDto>();
        public int AppId { get; set; }
        public string AppName { get; set; } = string.Empty;
        public string AppDescription { get; set; } = string.Empty;

        /// <summary>
        /// Indicates if this user authenticates via Azure AD (no password).
        /// True when AppSecret and Salt are null.
        /// </summary>
        public bool IsAzureAdUser => string.IsNullOrEmpty(AppSecret) && string.IsNullOrEmpty(Salt);

        [DisplayFormat(DataFormatString = "{0:MMM dd, yyyy}")]
        public DateTime CreatedDateTime { get; set; }
        public DateTime ModifiedDateTime { get; set; }
    }

    public class AuthenticateRequest
    {
        public string Email { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
    }

    public class AppAuthenticateRequest
    {
        public Guid AppClientId { get; set; }

        [DataType(DataType.Password)]
        public string AppSecret { get; set; } = string.Empty;
    }

    public class AppUserCredentials
    {
        public string Hash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public string EncryptionKey { get; set; } = string.Empty;
    }

    public class UserShortInfo
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }

    public class AppUserRoleDto
    {
        public int RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Request model for Azure AD authentication.
    /// Used when a user authenticates via Azure AD and the frontend sends user info to validate or create the user.
    /// </summary>
    public class AzureAuthenticateRequest
    {
        /// <summary>
        /// The actual email address from Azure AD claims.
        /// This is typically the 'email' claim or extracted from external user format.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// The User Principal Name (UPN) from Azure AD.
        /// This is the primary identifier for Azure AD authentication and should be treated as the key.
        /// </summary>
        public string? Upn { get; set; }

        /// <summary>
        /// The display name from Azure AD (account.name).
        /// </summary>
        public string? DisplayName { get; set; }

        /// <summary>
        /// The username from Azure AD (account.username).
        /// </summary>
        public string? Username { get; set; }
    }

    /// <summary>
    /// Request model for updating a user's role.
    /// </summary>
    public class UpdateUserRoleRequest
    {
        /// <summary>
        /// The user ID to update.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// The new role ID to assign.
        /// </summary>
        public int RoleId { get; set; }
    }
}
