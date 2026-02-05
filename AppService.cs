using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TPEmail.BusinessModels.RequestModels;
using TPEmail.BusinessModels.ResponseModels;
using TPEmail.Common.Helpers;
using TPEmail.Common.Security;
using TPEmail.BusinessModels.Enums;
using TPEmail.BusinessModels.Constants;
using TPEmail.DataAccess.Interface.Repository.v1_0;
using TPEmail.DataAccess.Interface.Service.v1_0;
using TPEmail.DataAccess.Services.Interfaces.Log;
using TPEmail.DataAccess.Services.Interfaces.Lookup;

namespace TPEmail.DataAccess.Service.v1_0
{
    public class AppService : IAppService
    {
        private readonly IAppRepository m_appRepository;
        private readonly IConfiguration m_configuration;
        private readonly Microsoft.AspNetCore.Http.IHttpContextAccessor m_httpContextAccessor;
        private readonly NLog.ILogger _logger;

        public AppService(IAppRepository appRepository, IConfiguration configuration, Microsoft.AspNetCore.Http.IHttpContextAccessor httpContextAccessor)
        {
            m_appRepository = appRepository;
            m_configuration = configuration;
            m_httpContextAccessor = httpContextAccessor;
            _logger = NLog.LogManager.GetCurrentClassLogger();
        }

        private string GetBaseUri()
        {
            var request = m_httpContextAccessor.HttpContext?.Request;
            if (request == null) return m_configuration["ApiBaseUrl"] ?? string.Empty;
            return string.Concat(request.Scheme, "://", request.Host.ToUriComponent());
        }

        #region Common
        public async Task<int> GetCount(string TableName, string Condition)
        {
            return await m_appRepository.GetCountAsync(TableName, Condition);
        }

        public async Task<int> GetCount(string TableName)
        {
            return await m_appRepository.GetCountAsync(TableName, string.Empty);
        }

        public async Task<List<DashboardEmailDto>> FindAdminDashboardData()
        {
            var data = await m_appRepository.FindAdminDashboardDataAsync();
            return data.ToList();
        }

        public async Task<List<Top10AppsDto>> FindTop10Apps()
        {
            var data = await m_appRepository.FindTop10AppsAsync();
            return data.ToList();
        }

        public async Task GenerateKeyConfiguration(string key, byte[] salt)
        {
            await m_appRepository.GenerateKeyConfigurationAsync(key, salt);
        }

        public async Task<KeyConfig> GetKeyConfig()
        {
            return await m_appRepository.GetKeyConfigAsync();
        }
        #endregion

        #region AppLookup
        public async Task<string> SaveUpdateEntity(AppLookup Data)
        {
            try
            {
                if (Data.Id == 0)
                {
                    // Generate appClient once on create if not provided (DB does not auto-generate it)
                    if (Data.AppClient == Guid.Empty)
                    {
                        Data.AppClient = Guid.NewGuid();
                    }
                    // Encrypt all sensitive fields on create
                    Data.AppSecret = EncryptionHelper.DataEncryptAsync(Data.AppSecret, null, "AppService.SaveUpdateEntity", Data.UserId);
                    Data.OwnerEmail = EncryptionHelper.DataEncryptAsync(Data.OwnerEmail, null, "AppService.SaveUpdateEntity.OwnerEmail", Data.UserId);
                    Data.AppOwner = EncryptionHelper.DataEncryptAsync(Data.AppOwner, null, "AppService.SaveUpdateEntity.AppOwner", Data.UserId);
                    Data.EmailServer = EncryptionHelper.DataEncryptAsync(Data.EmailServer, null, "AppService.SaveUpdateEntity.EmailServer", Data.UserId);
                    // Port is stored as encrypted string
                    if (Data.Port.HasValue)
                    {
                        Data.EncryptedPort = EncryptionHelper.DataEncryptAsync(Data.Port.Value.ToString(), null, "AppService.SaveUpdateEntity.Port", Data.UserId);
                    }
                    Data.IsEncrypted = true;
                }
                else
                {
                    // On update, encrypt sensitive fields that may have changed
                    Data.OwnerEmail = EncryptionHelper.DataEncryptAsync(Data.OwnerEmail, null, "AppService.SaveUpdateEntity.OwnerEmail", Data.UserId);
                    Data.AppOwner = EncryptionHelper.DataEncryptAsync(Data.AppOwner, null, "AppService.SaveUpdateEntity.AppOwner", Data.UserId);
                    Data.EmailServer = EncryptionHelper.DataEncryptAsync(Data.EmailServer, null, "AppService.SaveUpdateEntity.EmailServer", Data.UserId);
                    // Port is stored as encrypted string
                    if (Data.Port.HasValue)
                    {
                        Data.EncryptedPort = EncryptionHelper.DataEncryptAsync(Data.Port.Value.ToString(), null, "AppService.SaveUpdateEntity.Port", Data.UserId);
                    }
                    Data.IsEncrypted = true;
                }
                // On update (Id != 0), appClient is NOT regenerated; it remains unchanged

                var result = await m_appRepository.SaveUpdateEntityAsync(Data);
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveUpdateEntity (AppLookup): {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppLookup>> FindAppLookup()
        {
            try
            {
                var list = await m_appRepository.FindApplicationLookupAsync();
                var result = DecryptAppLookupList(list);
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppLookup: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppLookup>> FindAppLookup(int CurrentPage, int PageSize)
        {
            // Use database-level pagination - no in-memory processing
            var data = await m_appRepository.FindApplicationLookupAsync(CurrentPage, PageSize, null, null, null);
            return DecryptAppLookupList(data);
        }

        public async Task<IList<AppLookup>> FindAppLookup(int CurrentPage, int PageSize, string? searchTerm)
        {
            // Use database-level pagination and filtering - no in-memory processing
            var data = await m_appRepository.FindApplicationLookupAsync(CurrentPage, PageSize, searchTerm, null, null);
            return DecryptAppLookupList(data);
        }

        public async Task<IList<AppLookup>> FindAppLookup(string UserId, int CurrentPage, int PageSize)
        {
            // Use database-level pagination with userId filter - no in-memory processing
            var data = await m_appRepository.FindApplicationLookupAsync(CurrentPage, PageSize, null, UserId, null);
            return DecryptAppLookupList(data);
        }

        public async Task<IList<AppLookup>> FindAppLookup(string UserId, int CurrentPage, int PageSize, string? searchTerm)
        {
            // Use database-level pagination and filtering - no in-memory processing
            var data = await m_appRepository.FindApplicationLookupAsync(CurrentPage, PageSize, searchTerm, UserId, null);
            return DecryptAppLookupList(data);
        }

        public async Task<AppLookup> FindAppLookup(int Id)
        {
            var item = await m_appRepository.FindApplicationAsync(Id);
            return DecryptAppLookup(item);
        }

        public async Task<AppLookup> FindAppLookup(Guid AppClientId)
        {
            var item = await m_appRepository.FindApplicationAsync(AppClientId);
            return DecryptAppLookup(item);
        }

        private IList<AppLookup> DecryptAppLookupList(IList<AppLookup> list)
        {
            foreach (var item in list)
            {
                DecryptAppLookupFields(item);
            }
            return list;
        }

        private AppLookup DecryptAppLookup(AppLookup? item)
        {
            if (item != null)
            {
                DecryptAppLookupFields(item);
            }
            return item ?? new AppLookup();
        }

        /// <summary>
        /// Decrypts all sensitive fields in an AppLookup item if encryption flag is set.
        /// Sensitive fields: AppSecret, OwnerEmail, AppOwner, EmailServer, Port
        /// </summary>
        private void DecryptAppLookupFields(AppLookup item)
        {
            // Decrypt FromEmailAddress (always encrypted for non-internal apps)
            item.FromEmailAddress = DecryptSafely(item.FromEmailAddress, item.UserId);
            
            if (item.IsEncrypted)
            {
                // Decrypt all sensitive fields
                item.AppSecret = DecryptSafely(item.AppSecret, item.UserId);
                item.OwnerEmail = DecryptSafely(item.OwnerEmail, item.UserId);
                item.AppOwner = DecryptSafely(item.AppOwner, item.UserId);
                item.EmailServer = DecryptSafely(item.EmailServer, item.UserId);
                
                // Port is stored as encrypted string, decrypt and parse to int
                if (!string.IsNullOrEmpty(item.EncryptedPort))
                {
                    var decryptedPort = DecryptSafely(item.EncryptedPort, item.UserId);
                    if (int.TryParse(decryptedPort, out int portValue))
                    {
                        item.Port = portValue;
                    }
                }
            }
            else
            {
                // Legacy data - OwnerEmail might not be encrypted
                item.OwnerEmail = item.OwnerEmail ?? "";
            }
        }

        public async Task<int> UpdateApplicationApproval(int AppId)
        {
            return await m_appRepository.UpdateApplicationApprovalAsync(AppId);
        }

        public async Task<int> GetAppCount()
        {
            return await m_appRepository.GetAppCountAsync();
        }

        public async Task<int> GetAppCount(string? searchTerm)
        {
            // Use database-level count - no in-memory filtering
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return await GetAppCount();
            }
            var countResult = await m_appRepository.GetApplicationCountAsync(searchTerm, null, null);
            return countResult.TotalCount;
        }

        public async Task<int> GetAppCount(string userId, string? searchTerm)
        {
            // Use database-level count with filters - no in-memory filtering
            var countResult = await m_appRepository.GetApplicationCountAsync(searchTerm, userId, null);
            return countResult.TotalCount;
        }
        #endregion

        #region EmailServiceLookup
        // Email service types are static - cannot be modified via API
        // Services: O365=1, Mailkit=2, ExchangeServer=3, SendGrid=4 (defined in CommonUtils.Services enum)
        public Task<int> SaveUpdateEntity(EmailServiceLookup Data)
        {
            throw new NotSupportedException("Email service types are static and cannot be modified. See CommonUtils.Services enum.");
        }

        // Email service types are now returned from static enum (CommonUtils.Services)
        // No database table needed - TP Internal=0, O365=1, Mailkit=2, Exchange Server=3, SendGrid=4
        private static readonly List<EmailServiceLookup> _staticEmailServices = new List<EmailServiceLookup>
        {
            new EmailServiceLookup { Id = 0, ServiceName = "TP Internal", Active = true, CreationDateTime = DateTime.MinValue },
            new EmailServiceLookup { Id = 1, ServiceName = "O365", Active = true, CreationDateTime = DateTime.MinValue },
            new EmailServiceLookup { Id = 2, ServiceName = "Mailkit", Active = true, CreationDateTime = DateTime.MinValue },
            new EmailServiceLookup { Id = 3, ServiceName = "Exchange Server", Active = true, CreationDateTime = DateTime.MinValue },
            new EmailServiceLookup { Id = 4, ServiceName = "SendGrid", Active = true, CreationDateTime = DateTime.MinValue }
        };

        public Task<IEnumerable<EmailServiceLookup>> GetAllEmailServiceLookups()
        {
            return Task.FromResult<IEnumerable<EmailServiceLookup>>(_staticEmailServices);
        }

        public async Task<IEnumerable<EmailServiceLookup>> GetEmailServiceLookup(int CurrentPage, int PageSize)
        {
            var data = await GetAllEmailServiceLookups();
            return data.Skip((CurrentPage - 1) * PageSize).Take(PageSize).ToList();
        }

        public async Task<int> GetEmailServiceLookupCount()
        {
            var data = await GetAllEmailServiceLookups();
            return data.Count();
        }

        public Task<EmailServiceLookup> GetEmailServiceLookupById(int Id)
        {
            var service = _staticEmailServices.FirstOrDefault(s => s.Id == Id);
            if (service == null)
                throw new KeyNotFoundException(string.Format(MessageConstants.EmailServiceLookupNotFoundForIdFormat, Id));
            return Task.FromResult(service);
        }

        // Wrapper methods for backward compatibility with Manager layer - explicit interface implementation
        async Task<IEnumerable<EmailServiceLookup>> IEmailServiceLookup.GetAll()
        {
            return await GetAllEmailServiceLookups();
        }

        async Task<int> IEmailServiceLookup.GetCount()
        {
            return await GetEmailServiceLookupCount();
        }

        async Task<EmailServiceLookup> IEmailServiceLookup.GetById(int Id)
        {
            return await GetEmailServiceLookupById(Id);
        }
        #endregion

        #region ActivityLog
        public async Task<int> Log(ActivityLog Data)
        {
            return await m_appRepository.LogAsync(Data);
        }

        public async Task<int> Log(int LogType, string Description, string Path)
        {
            return await LogInternal(LogType, Description, Path, null);
        }

        public async Task<int> Log(int LogType, string Description, string Path, string User)
        {
            return await LogInternal(LogType, Description, Path, User);
        }

        private async Task<int> LogInternal(int LogType, string Description, string Path, string? User)
        {
            return await m_appRepository.LogAsync(new ActivityLog
            {
                LogTypeLookupId = LogType,
                Description = Description,
                Url = Path,
                LoggedBy = User
            });
        }

        public async Task<IEnumerable<ActivityLog>> GetAllActivityLogs()
        {
            return await m_appRepository.GetAllAsync();
        }

        public async Task<IList<ActivityLog>> GetAllActivityLogs(int PageNumber, int PageSize)
        {
            var data = await m_appRepository.GetAllAsync();
            return data.Skip((PageNumber - 1) * PageSize).Take(PageSize).ToList();
        }

        public async Task<int> SignInLog(string userId, string email, string ip, int success)
        {
            return await m_appRepository.AppLoginAsync(new AppLogin
            {
                UserId = userId,
                Email = email,
                IPAddress = ip,
                Success = success
            });
        }

        public async Task<int> ActivityLogCount()
        {
            var data = await m_appRepository.GetAllAsync();
            return data.Count();
        }

        // Wrapper methods for backward compatibility with Manager layer - explicit interface implementation
        async Task<IEnumerable<ActivityLog>> IActivityLog.GetAll()
        {
            return await GetAllActivityLogs();
        }

        async Task<IList<ActivityLog>> IActivityLog.GetAll(int PageNumber, int PageSize)
        {
            return await GetAllActivityLogs(PageNumber, PageSize);
        }

        async Task<int> IActivityLog.Count()
        {
            return await ActivityLogCount();
        }
        #endregion

        #region ErrorLog
        public async Task<int> SaveErrorLog(string Error, string Path)
        {
            return await SaveErrorLogInternal(Error, Path, null);
        }

        public async Task<int> SaveErrorLog(string Error, string Path, string User)
        {
            return await SaveErrorLogInternal(Error, Path, User);
        }

        private async Task<int> SaveErrorLogInternal(string Error, string Path, string? User)
        {
            var errorLog = new ErrorLog { Error = Error, ErrorSource = Path, LoggedBy = User ?? string.Empty };
            return await m_appRepository.SaveAsync(errorLog);
        }
        #endregion

        #region Pagination
        public Uri GetPageUri(PaginationFilter filter, string route)
        {
            var endpointUri = new Uri(string.Concat(GetBaseUri(), route));
            var modifiedUri = QueryHelpers.AddQueryString(endpointUri.ToString(), "pageNumber", filter.PageNumber.ToString());
            modifiedUri = QueryHelpers.AddQueryString(modifiedUri, "pageSize", filter.PageSize.ToString());
            return new Uri(modifiedUri);
        }
        #endregion

        #region Account / JWT
        public string GenerateUserTokenAsync(AppUserGetDto Data)
        {
            try
            {
                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, Data.UserId.ToString()));
                claims.Add(new Claim(ClaimTypes.Name, Data.Email));
                claims.Add(new Claim("username", Data.Username ?? Data.Email));

                if (Data.Applications != null && Data.Applications.Count > 0)
                {
                    if (Data.Applications.Count == 1)
                    {
                        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Data.Applications.First().AppClient.ToString()));
                    }
                    else
                    {
                        string appClients = string.Join(";", Data.Applications.Select(x => x.AppClient.ToString()));
                        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, appClients));
                    }
                }
                else
                {
                    claims.Add(new Claim(JwtRegisteredClaimNames.Jti, string.Empty));
                }

                if (Data.Roles != null)
                {
                    foreach (var role in Data.Roles)
                    {
                        // Use uppercase role name to match [Authorize(Roles = "ADMIN")] attribute
                        claims.Add(new Claim(ClaimTypes.Role, role.RoleName.ToUpper()));
                        // Add roleId for numeric comparison
                        claims.Add(new Claim("roleId", role.RoleId.ToString()));
                    }
                }

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtKey = Environment.GetEnvironmentVariable("tpjwtkey") ?? m_configuration["Jwt:Key"];
                if (string.IsNullOrEmpty(jwtKey))
                {
                    throw new InvalidOperationException(MessageConstants.JwtKeyNotConfigured);
                }

                var tokenKey = Encoding.UTF8.GetBytes(jwtKey);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claimsIdentity,
                    Issuer = Environment.GetEnvironmentVariable("tpjwtissuer") ?? m_configuration["Jwt:Issuer"],
                    Audience = Environment.GetEnvironmentVariable("tpjwtaudience") ?? m_configuration["Jwt:Audience"],
                    NotBefore = DateTime.UtcNow,
                    Expires = DateTime.UtcNow.AddHours(2),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GenerateUserTokenAsync: {ex.Message}");
                throw;
            }
        }

        public Guid? ValidateTokenAsync(string Token)
        {
            try
            {
                if (string.IsNullOrEmpty(Token)) return null;

                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtKey = Environment.GetEnvironmentVariable("tpjwtkey") ?? m_configuration["Jwt:Key"];
                if (string.IsNullOrEmpty(jwtKey))
                {
                    throw new InvalidOperationException(MessageConstants.JwtKeyNotConfigured);
                }

                var key = Encoding.UTF8.GetBytes(jwtKey);

                tokenHandler.ValidateToken(Token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = Environment.GetEnvironmentVariable("tpjwtissuer") ?? m_configuration["Jwt:Issuer"],
                    ValidAudience = Environment.GetEnvironmentVariable("tpjwtaudience") ?? m_configuration["Jwt:Audience"]
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = new Guid(jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value);
                return userId;
            }
            catch
            {
                return null;
            }
        }
        #endregion

        #region User / AppService
        public async Task<Guid> Registration(AppUser Data)
        {
            try
            {
                if (Data == null) throw new ArgumentNullException(nameof(Data));
                if (string.IsNullOrEmpty(Data.Email)) throw new ArgumentNullException(nameof(Data.Email), MessageConstants.EmailIsRequired);
                if (string.IsNullOrEmpty(Data.AppSecret)) throw new ArgumentNullException(nameof(Data.AppSecret), MessageConstants.PasswordIsRequired);

                // Generate a new UserId for the new user
                Data.UserId = Guid.NewGuid();

                // Generate blind index BEFORE encryption (uses plaintext email)
                // This allows searchable lookups on encrypted data
                Data.EmailBlindIndex = EncryptionHelper.GenerateBlindIndex(Data.Email.Trim());

                // Email: MUST be encrypted with AES-256-GCM (audit requirement)
                Data.Email = EncryptionHelper.DataEncryptAsync(Data.Email.Trim(), null, "AppService.Registration", Data.Username);
                
                // UPN: Stored as PLAINTEXT for now (encryption-ready, not encryption-forced)
                // Schema supports future encryption via upnblindindex and upnencversion columns
                Data.Upn = Data.Upn?.Trim();
                
                AppUserCredentials credentials = PasswordHashingService.GenerateArgonHash(Data.AppSecret);
                Data.AppSecret = credentials.Hash;
                Data.Salt = credentials.Salt;
                Data.EncryptionKey = credentials.EncryptionKey;

                Guid UserId = await m_appRepository.SaveAppUserAsync(Data);

                if (!UserId.Equals(Guid.Empty))
                {
                    AppUserRole UserRoleData = new AppUserRole
                    {
                        UserId = UserId,
                        RoleId = (Data.RoleId == null) ? (int)RoleType.USER : (int)Data.RoleId
                    };

                    await m_appRepository.SaveUserRoleAsync(UserRoleData);

                    await m_appRepository.SaveAppUserCredentialsLogAsync(new PasswordUpdate
                    {
                        UserId = UserId,
                        NoOfUpdate = 0,
                        CreatedBy = UserId.ToString(),
                        ModifiedBy = UserId.ToString()
                    });
                }

                return UserId;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in Registration: {ex.Message}");
                throw;
            }
        }

        public async Task<AppUserGetDto> Authenticate(AuthenticateRequest Data)
        {
            try
            {
                var UserData = await FindUserByEmailAsync(Data.Email);
                if (UserData == null)
                {
                    throw new KeyNotFoundException(string.Format(MessageConstants.NoEmailFoundWithFormat, Data.Email));
                }

                if (!VerifyPassword(Data.Password, UserData.AppSecret, UserData.Salt))
                {
                    throw new UnauthorizedAccessException(MessageConstants.InvalidCredentials);
                }

                return UserData;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in Authenticate: {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateAppUserCredentials(AppUser Data)
        {
            try
            {
                // Validate that a password is provided
                if (string.IsNullOrEmpty(Data.AppSecret))
                {
                    throw new ArgumentException("Password is required for credential update");
                }

                Data.Email = EncryptionHelper.DataEncryptAsync(Data.Email, null, "AppService.UpdateAppUserCredentials", Data.UserId.ToString());

                AppUserCredentials credentials = PasswordHashingService.GenerateArgonHash(Data.AppSecret);
                Data.AppSecret = credentials.Hash;
                Data.Salt = credentials.Salt;
                Data.EncryptionKey = credentials.EncryptionKey;

                await m_appRepository.AppSecreteUpdateLogAsync(Data);
                return await m_appRepository.UpdateAppUserCredentialsAsync(Data);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UpdateAppUserCredentials: {ex.Message}");
                throw;
            }
        }

        public bool VerifyPassword(string password, string hash, string salt)
        {
            try
            {
                //
                // AD users have null hash/salt - they cannot authenticate via password
                if (string.IsNullOrEmpty(hash) || string.IsNullOrEmpty(salt))
                {
                    return false;
                }

                if (salt != "ENCRYPTED")
                {
                    try
                    {
                        byte[] saltBytes = Convert.FromBase64String(salt);
                        byte[] hashBytes = Convert.FromBase64String(hash);

                        if (PasswordHashingService.VerifyArgonHash(password, saltBytes, hashBytes))
                        {
                            return true;
                        }

                        if (PasswordHashingService.VerifyPbkdf2Raw(password, saltBytes, hashBytes))
                        {
                            return true;
                        }
                    }
                    catch
                    {
                        // Fall through
                    }
                }

                try
                {
                    if (salt != "ENCRYPTED" && !string.IsNullOrEmpty(salt) && salt.Length > 20)
                    {
                        return false;
                    }

                    string cleanHash = hash;
                    if (hash != null && hash.StartsWith("md5", StringComparison.OrdinalIgnoreCase))
                    {
                        cleanHash = hash.Substring(3);
                    }

                    string decryptedSecret = EncryptionHelper.DataDecrypt(cleanHash, null, "AppService.VerifyPassword");
                    return password == decryptedSecret;
                }
                catch
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in VerifyPassword: {ex.Message}");
                throw;
            }
        }

        public string GenerateJWTTokenAsync(AppUserGetDto Source)
        {
            return GenerateUserTokenAsync(Source);
        }

        public async Task<UserDetailsType> UserStateAsync(AuthenticateRequest Data)
        {
            try
            {
                var UserData = await FindUserByEmailAsync(Data.Email);
                if (UserData == null) return UserDetailsType.USER_NOT_FOUND;
                
                // Check if this is an Azure AD user (no password/salt)
                if (string.IsNullOrEmpty(UserData.AppSecret) || string.IsNullOrEmpty(UserData.Salt))
                {
                    return UserDetailsType.AZURE_AD_USER;
                }
                
                if (!VerifyPassword(Data.Password, UserData.AppSecret, UserData.Salt)) return UserDetailsType.INVALID_CREDENTIALS;
                if (UserData.Active == 0) return UserDetailsType.UNAUTHORIZED;

                return UserDetailsType.USER_ALREADY_EXISTS;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UserStateAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<ApiResponse<string>> AuthenticateUserAsync(AuthenticateRequest Data)
        {
            try
            {
                var Type = await UserStateAsync(Data);

                switch (Type)
                {
                    case UserDetailsType.USER_NOT_FOUND:
                        return new ApiResponse<string>(
                            ResultCodes.USER_NOT_FOUND,
                            null,
                            new[] { string.Format(MessageConstants.UserWithEmailNotFoundFormat, Data.Email) }
                        );

                    case UserDetailsType.INVALID_CREDENTIALS:
                        return new ApiResponse<string>(
                            ResultCodes.INVALID_CREDENTIALS,
                            null,
                            new[] { MessageConstants.InvalidEmailOrPassword }
                        );

                    case UserDetailsType.UNAUTHORIZED:
                        return new ApiResponse<string>(
                            ResultCodes.USER_NOT_APPROVED,
                            null,
                            new[] { MessageConstants.UserPendingApprovalContactAdmin }
                        );

                    case UserDetailsType.AZURE_AD_USER:
                        return new ApiResponse<string>(
                            ResultCodes.AZURE_AD_LOGIN_REQUIRED,
                            null,
                            new[] { "This account uses Azure AD authentication. Please use the 'Login with Azure AD' option." }
                        );
                }

                var UserData = await FindUserByEmailAsync(Data.Email);
                if (UserData == null)
                {
                    return new ApiResponse<string>(
                        ResultCodes.USER_NOT_FOUND,
                        null,
                        new[] { string.Format(MessageConstants.NoUserFoundWithEmailFormat, Data.Email) }
                    );
                }

                string Token = GenerateJWTTokenAsync(UserData);

                return new ApiResponse<string>(
                    ResultCodes.SUCCESS,
                    new[] { Token },
                    new[] { MessageConstants.AuthenticationSuccessful }
                );
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in AuthenticateUserAsync: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Authenticates a user via Azure AD. If the user doesn't exist, creates them with User role.
        /// Azure AD users are differentiated by having no password (appsecret/salt are null).
        /// UPN is the primary identifier for Azure AD users. Email and UPN are stored separately.
        /// </summary>
        public async Task<ApiResponse<string>> AuthenticateAzureUserAsync(AzureAuthenticateRequest Data)
        {
            try
            {
                // UPN is the primary identifier for Azure AD - prefer it over email
                string? upn = !string.IsNullOrWhiteSpace(Data?.Upn) 
                    ? Data.Upn.Trim().ToLowerInvariant() 
                    : !string.IsNullOrWhiteSpace(Data?.Email) 
                        ? Data.Email.Trim().ToLowerInvariant() 
                        : null;

                if (string.IsNullOrWhiteSpace(upn))
                {
                    return new ApiResponse<string>(
                        ResultCodes.VALIDATION_FAILURE,
                        null,
                        new[] { "UPN is required for Azure AD authentication" }
                    );
                }

                // First, try to find existing user by UPN (exact match for Azure AD users)
                var existingUser = await FindUserByUpnAsync(upn);

                // If not found by UPN, also check by email (in case a regular user tries Azure AD login)
                if (existingUser == null && !string.IsNullOrWhiteSpace(Data?.Email))
                {
                    existingUser = await FindUserByEmailAsync(Data.Email.Trim().ToLowerInvariant());
                }

                if (existingUser != null)
                {
                    // Check if this is a regular user (has password) trying to use Azure AD
                    if (!string.IsNullOrEmpty(existingUser.AppSecret) && !string.IsNullOrEmpty(existingUser.Salt))
                    {
                        return new ApiResponse<string>(
                            ResultCodes.INVALID_CREDENTIALS,
                            null,
                            new[] { "This account uses password authentication. Please use the standard login form." }
                        );
                    }

                    // User exists - check if active
                    if (existingUser.Active == 0)
                    {
                        return new ApiResponse<string>(
                            ResultCodes.USER_NOT_APPROVED,
                            null,
                            new[] { MessageConstants.UserPendingApprovalContactAdmin }
                        );
                    }

                    // Generate token for existing Azure AD user
                    string token = GenerateJWTTokenAsync(existingUser);
                    return new ApiResponse<string>(
                        ResultCodes.SUCCESS,
                        new[] { token },
                        new[] { MessageConstants.AuthenticationSuccessful }
                    );
                }

                // User doesn't exist - fetch user details from Graph API using UPN
                _logger.Info($"New Azure AD user login attempt. Fetching user details from Graph API for: {upn}");
                
                ADUser? adUser = await GetADUserAsync(upn);
                
                string email;
                string userName;
                
                if (adUser != null)
                {
                    // Use Graph API data - mail is the actual email, userPrincipalName is UPN
                    email = !string.IsNullOrWhiteSpace(adUser.Mail) 
                        ? adUser.Mail.Trim().ToLowerInvariant()
                        : !string.IsNullOrWhiteSpace(Data?.Email)
                            ? Data.Email.Trim().ToLowerInvariant()
                            : upn; // Fallback to UPN if no email found
                    
                    userName = !string.IsNullOrWhiteSpace(adUser.DisplayName) 
                        ? adUser.DisplayName 
                        : !string.IsNullOrWhiteSpace(Data?.DisplayName) 
                            ? Data.DisplayName 
                            : upn.Split('@')[0];
                    
                    _logger.Info($"Graph API user found: DisplayName={adUser.DisplayName}, Mail={adUser.Mail}, UPN={adUser.UserPrincipalName}");
                }
                else
                {
                    // Graph API call failed - use data from frontend
                    email = !string.IsNullOrWhiteSpace(Data?.Email) 
                        ? Data.Email.Trim().ToLowerInvariant()
                        : upn;
                    
                    userName = !string.IsNullOrWhiteSpace(Data?.DisplayName) 
                        ? Data.DisplayName 
                        : !string.IsNullOrWhiteSpace(Data?.Username) 
                            ? Data.Username 
                            : upn.Split('@')[0];
                    
                    _logger.Warn($"Graph API user not found for {upn}, using frontend data");
                }

                // Create new Azure AD user (auto-approved with User role)
                var newUser = new AppUser
                {
                    UserId = Guid.NewGuid(),
                    Email = email, // Store actual email (will be encrypted)
                    Upn = upn, // Store UPN separately (plaintext for lookup)
                    Username = userName,
                    AppSecret = null, // No password for Azure AD users
                    Salt = null,
                    EncryptionKey = null,
                    Active = 1, // Azure AD users are auto-approved
                    RoleId = (int)RoleType.USER // Assign User role by default
                };

                // Generate blind index for email lookup (use the actual email)
                newUser.EmailBlindIndex = EncryptionHelper.GenerateBlindIndex(email);
                // Encrypt email for storage
                newUser.Email = EncryptionHelper.DataEncryptAsync(email, null, "AppService.AuthenticateAzureUserAsync", newUser.Username);

                // Save the new user
                Guid userId = await m_appRepository.SaveAppUserAsync(newUser);

                if (!userId.Equals(Guid.Empty))
                {
                    // Assign User role
                    await m_appRepository.SaveUserRoleAsync(new AppUserRole
                    {
                        UserId = userId,
                        RoleId = (int)RoleType.USER
                    });

                    _logger.Info($"New Azure AD user created: UPN={upn}, Email={email}, UserId={userId}");

                    // Fetch the newly created user with roles
                    var createdUser = await FindUserByUpnAsync(upn);
                    if (createdUser != null && createdUser.Roles != null && createdUser.Roles.Count > 0)
                    {
                        string token = GenerateJWTTokenAsync(createdUser);
                        return new ApiResponse<string>(
                            ResultCodes.SUCCESS,
                            new[] { token },
                            new[] { "Azure AD authentication successful. Welcome!" }
                        );
                    }
                    else
                    {
                        // Role not found after creation - this shouldn't happen, but handle gracefully
                        _logger.Warn($"User created but roles not found immediately. Retrying role fetch for userId: {userId}");
                        
                        // Manually construct user with role for token generation
                        var userWithRole = new AppUserGetDto
                        {
                            UserId = userId,
                            Email = email,
                            Username = userName,
                            Upn = upn,
                            Active = 1,
                            Roles = new List<AppUserRoleDto> 
                            { 
                                new AppUserRoleDto { RoleId = (int)RoleType.USER, RoleName = "User" } 
                            }
                        };
                        
                        string token = GenerateJWTTokenAsync(userWithRole);
                        return new ApiResponse<string>(
                            ResultCodes.SUCCESS,
                            new[] { token },
                            new[] { "Azure AD authentication successful. Welcome!" }
                        );
                    }
                }

                return new ApiResponse<string>(
                    ResultCodes.REGISTRATION_FAILURE,
                    null,
                    new[] { "Failed to create Azure AD user account" }
                );
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in AuthenticateAzureUserAsync: {ex.Message}");
                return new ApiResponse<string>(
                    ResultCodes.SERVER_ERROR,
                    null,
                    new[] { "An error occurred during Azure AD authentication" }
                );
            }
        }

        /// <summary>
        /// Finds a user by their UPN (User Principal Name). Used for Azure AD user lookup.
        /// </summary>
        public async Task<AppUserGetDto?> FindUserByUpnAsync(string upn)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(upn)) return null;

                AppUserGetDto? result = await m_appRepository.FindAppUserByUpnAsync(upn.Trim().ToLowerInvariant());
                if (result != null)
                {
                    result.Email = DecryptSafely(result.Email, result.UserId.ToString());
                    // UPN is stored as plaintext, no decryption needed
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindUserByUpnAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppUserGetDto>> FindAllAppUser()
        {
            try
            {
                var userList = await m_appRepository.FindAppUsersAsync();
                foreach (var user in userList)
                {
                    user.Email = DecryptSafely(user.Email, user.UserId.ToString());
                    user.Upn = DecryptSafely(user.Upn, user.UserId.ToString());
                }
                return userList.ToList();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAllAppUser: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppUserGetDto>> FindAllAppUser(int CurrentPage, int PageSize)
        {
            // Use database-level pagination - no in-memory processing
            var data = await m_appRepository.FindAppUsersAsync(CurrentPage, PageSize, null, null);
            foreach (var user in data)
            {
                user.Email = DecryptSafely(user.Email, user.UserId.ToString());
                user.Upn = DecryptSafely(user.Upn, user.UserId.ToString());
            }
            return data;
        }

        public async Task<IList<AppUserGetDto>> FindAllAppUser(int CurrentPage, int PageSize, string? searchTerm)
        {
            // Use database-level pagination and filtering - no in-memory processing
            var data = await m_appRepository.FindAppUsersAsync(CurrentPage, PageSize, searchTerm, null, null, null);
            foreach (var user in data)
            {
                user.Email = DecryptSafely(user.Email, user.UserId.ToString());
                user.Upn = DecryptSafely(user.Upn, user.UserId.ToString());
            }
            return data;
        }

        public async Task<IList<AppUserGetDto>> FindAllAppUser(int CurrentPage, int PageSize, string? searchTerm, int? roleId, int? active, string? sortBy)
        {
            // Convert int? active to bool? for repository
            bool? activeFilter = active.HasValue ? (active.Value == 1) : null;
            
            var data = await m_appRepository.FindAppUsersAsync(CurrentPage, PageSize, searchTerm, activeFilter, roleId, sortBy);
            foreach (var user in data)
            {
                user.Email = DecryptSafely(user.Email, user.UserId.ToString());
                user.Upn = DecryptSafely(user.Upn, user.UserId.ToString());
            }
            return data;
        }

        public async Task<int> GetUserCount()
        {
            return await m_appRepository.GetAppUserCountAsync();
        }

        public async Task<int> GetUserCount(string? searchTerm)
        {
            // Use database-level count - no in-memory filtering
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return await GetUserCount();
            }
            var countResult = await m_appRepository.GetUserCountAsync(searchTerm, null, null);
            return countResult.TotalCount;
        }

        public async Task<int> GetUserCount(string? searchTerm, int? roleId, int? active)
        {
            // Convert int? active to bool? for repository
            bool? activeFilter = active.HasValue ? (active.Value == 1) : null;
            var countResult = await m_appRepository.GetUserCountAsync(searchTerm, activeFilter, roleId);
            return countResult.TotalCount;
        }

        public async Task<int> GetCount()
        {
            return await GetUserCount();
        }

        public async Task<AppUserGetDto?> FindUserByEmailAsync(string Email)
        {
            try
            {
                // Use blind index for searchable lookup (deterministic hash of email)
                string emailBlindIndex = EncryptionHelper.GenerateBlindIndex(Email);
                AppUserGetDto? result = await m_appRepository.FindAppUserByEmailAsync(emailBlindIndex);
                if (result != null)
                {
                    result.Email = DecryptSafely(result.Email, result.UserId.ToString());
                    // UPN is stored as plaintext, no decryption needed
                    // result.Upn = DecryptSafely(result.Upn, result.UserId.ToString());
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindUserByEmailAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<AppUserGetDto?> FindUserByIdAsync(string UserId)
        {
            try
            {
                AppUserGetDto? result = await m_appRepository.FindAppUserByIdAsync(UserId);
                if (result != null)
                {
                    result.Email = DecryptSafely(result.Email, UserId);
                    //result.Upn = DecryptSafely(result.Upn, UserId);
                    result.Upn = result.Upn;
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindUserByIdAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateVerifiedUserAsync(Guid UserId)
        {
            return await m_appRepository.UpdateToVerifiedUserAsync(UserId);
        }

        public async Task<int> UpdateUserRoleAsync(Guid userId, int newRoleId, string modifiedBy)
        {
            return await m_appRepository.UpdateUserRoleAsync(userId, newRoleId, modifiedBy);
        }

        public async Task<IList<AppRole>> FindAppRole()
        {
            return await m_appRepository.FindAppRoleAsync();
        }
        #endregion

        #region Microsoft Graph API
        private static readonly HttpClient s_graphHttpClient = new();
        private static string? s_graphToken;
        private static DateTime s_graphTokenExpiry = DateTime.MinValue;
        private static readonly SemaphoreSlim s_tokenLock = new(1, 1);

        private const string GRAPH_URL = "https://graph.microsoft.com/v1.0";
        private const string USER_SELECT = "id,displayName,givenName,surname,userPrincipalName,mail,jobTitle,department,officeLocation,mobilePhone,companyName";

        private async Task<string> GetGraphTokenAsync()
        {
            await s_tokenLock.WaitAsync();
            try
            {
                if (!string.IsNullOrEmpty(s_graphToken) && DateTime.UtcNow < s_graphTokenExpiry.AddMinutes(-5))
                    return s_graphToken;

                var clientId = Environment.GetEnvironmentVariable("tpgraphclientid") ?? "";
                var clientSecret = Environment.GetEnvironmentVariable("tpgraphclientsecret") ?? "";
                var tenantId = Environment.GetEnvironmentVariable("tpgraphtenantid") ?? "";

                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                    ["scope"] = "https://graph.microsoft.com/.default",
                    ["grant_type"] = "client_credentials"
                });

                var response = await s_graphHttpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                s_graphToken = doc.RootElement.GetProperty("access_token").GetString()!;
                s_graphTokenExpiry = DateTime.UtcNow.AddSeconds(doc.RootElement.GetProperty("expires_in").GetInt32());
                return s_graphToken;
            }
            finally { s_tokenLock.Release(); }
        }

        public async Task<ADUser?> GetADUserAsync(string upn)
        {
            if (string.IsNullOrWhiteSpace(upn)) return null;
            try
            {
                var token = await GetGraphTokenAsync();
                var request = new HttpRequestMessage(HttpMethod.Get, $"{GRAPH_URL}/users/{Uri.EscapeDataString(upn)}?$select={USER_SELECT}");
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                var response = await s_graphHttpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode) return null;
                var json = await response.Content.ReadAsStringAsync();
                return System.Text.Json.JsonSerializer.Deserialize<ADUser>(json, s_jsonOptions);
            }
            catch { return null; }
        }

        public async Task<object?> GetADUserPhotoAsync(string upn)
        {
            if (string.IsNullOrWhiteSpace(upn)) return null;
            try
            {
                var token = await GetGraphTokenAsync();
                var url = $"{GRAPH_URL}/users/{Uri.EscapeDataString(upn)}/photo/$value";
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                var response = await s_graphHttpClient.SendAsync(request);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return new { success = false, statusCode = (int)response.StatusCode, error = errorContent };
                }
                
                var bytes = await response.Content.ReadAsByteArrayAsync();
                var contentType = response.Content.Headers.ContentType?.MediaType ?? "image/jpeg";
                return new { success = true, data = $"data:{contentType};base64,{Convert.ToBase64String(bytes)}" };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static readonly System.Text.Json.JsonSerializerOptions s_jsonOptions = new() { PropertyNameCaseInsensitive = true };

        private async Task<ADUserSearchResponse> SearchADUsersWithFilterAsync(string filter)
        {
            try
            {
                var token = await GetGraphTokenAsync();
                var url = $"{GRAPH_URL}/users?$filter={Uri.EscapeDataString(filter)}&$select={USER_SELECT}&$count=true";
                _logger.Debug($"Graph API URL: {url}");
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                request.Headers.Add("ConsistencyLevel", "eventual");
                var response = await s_graphHttpClient.SendAsync(request);
                var json = await response.Content.ReadAsStringAsync();
                _logger.Debug($"Graph API Response: {response.StatusCode} - {json}");
                if (!response.IsSuccessStatusCode) return new ADUserSearchResponse();
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var users = new List<ADUser>();
                if (doc.RootElement.TryGetProperty("value", out var valueArray))
                {
                    foreach (var item in valueArray.EnumerateArray())
                        users.Add(System.Text.Json.JsonSerializer.Deserialize<ADUser>(item.GetRawText(), s_jsonOptions)!);
                }
                return new ADUserSearchResponse { Users = users, Count = users.Count };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Graph API Search Error: {ex.Message}");
                return new ADUserSearchResponse();
            }
        }

        public Task<ADUserSearchResponse> SearchADUsersByEmailAsync(string term) =>
            string.IsNullOrWhiteSpace(term) ? Task.FromResult(new ADUserSearchResponse())
            : SearchADUsersWithFilterAsync($"startsWith(userPrincipalName,'{term.Replace("'", "''")}')");

        public Task<ADUserSearchResponse> SearchADUsersByDisplayNameAsync(string term) =>
            string.IsNullOrWhiteSpace(term) ? Task.FromResult(new ADUserSearchResponse())
            : SearchADUsersWithFilterAsync($"startsWith(displayName,'{term.Replace("'", "''")}')");

        public Task<ADUserSearchResponse> SearchADUsersByFirstNameAsync(string term) =>
            string.IsNullOrWhiteSpace(term) ? Task.FromResult(new ADUserSearchResponse())
            : SearchADUsersWithFilterAsync($"startsWith(givenName,'{term.Replace("'", "''")}')");

        public Task<ADUserSearchResponse> SearchADUsersByLastNameAsync(string term) =>
            string.IsNullOrWhiteSpace(term) ? Task.FromResult(new ADUserSearchResponse())
            : SearchADUsersWithFilterAsync($"startsWith(surname,'{term.Replace("'", "''")}')");

        public Task<ADUserSearchResponse> SearchADUsersAsync(string term) =>
            string.IsNullOrWhiteSpace(term) ? Task.FromResult(new ADUserSearchResponse())
            : SearchADUsersWithFilterAsync($"startsWith(userPrincipalName,'{term.Replace("'", "''")}') or startsWith(displayName,'{term.Replace("'", "''")}') or startsWith(givenName,'{term.Replace("'", "''")}') or startsWith(surname,'{term.Replace("'", "''")}')");
        #endregion

        #region Helpers
        private string DecryptSafely(string? cipherText, string? userId = null) =>
            EncryptionHelper.DecryptSafely(cipherText, null, "AppService.DecryptSafely", userId);
        #endregion
    }
}
