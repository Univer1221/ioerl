using Dapper;
using System.Data;
using TPEmail.BusinessModels.RequestModels;
using TPEmail.BusinessModels.ResponseModels;
using TPEmail.Common.Data;
using TPEmail.BusinessModels.Enums;
using TPEmail.DataAccess.Interface.Repository.v1_0;
using TPEmail.BusinessModels.Constants;

namespace TPEmail.DataAccess.Repository.v1_0
{
    public class AppRepository : IAppRepository
    {
        private readonly DapperContext m_dapperContext;
        private readonly NLog.ILogger _logger;

        public AppRepository(DapperContext dapperContext)
        {
            m_dapperContext = dapperContext;
            _logger = NLog.LogManager.GetCurrentClassLogger();
        }

        #region Common
        public async Task<int> GetCountAsync(string TableName, string Condition)
        {
            try
            {
                // Map entity names to actual database table names
                string actualTableName = TableName switch
                {
                    "AppUser" => "dbo.tpm_user",
                    "Application" => "dbo.tpm_application",
                    "Email" => "dbo.tpm_email",
                    "EmailAttachment" => "dbo.tpm_emailattachment",
                    "EmailRecipient" => "dbo.tpm_emailrecipient",
                    "ActivityLog" => "dbo.tpm_activitylog",
                    "ErrorLog" => "dbo.tpm_errorlog",
                    "LoginAudit" => "dbo.tpm_loginaudit",
                    "LogType" => "dbo.tpm_logtype",
                    "Notification" => "dbo.tpm_notification",
                    "Role" => "dbo.tpm_role",
                    "SecretUpdate" => "dbo.tpm_secretupdate",
                    "Ticket" => "dbo.tpm_ticket",
                    "UserRole" => "dbo.tpm_userrole",
                    _ => $"dbo.{TableName.ToLower()}" // Default: assume it's a table name with dbo schema
                };

                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@tablename", actualTableName);
                parameters.Add("@condition", Condition);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.QueryFirstAsync<int>(StoredProcedureNames.SelectAppCount, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetCountAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<DashboardEmailDto>> FindAdminDashboardDataAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<DashboardEmailDto>(StoredProcedureNames.SelectEmailCount, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAdminDashboardDataAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<Top10AppsDto>> FindTop10AppsAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<Top10AppsDto>(StoredProcedureNames.SelectTop10Apps, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindTop10AppsAsync: {ex.Message}");
                throw;
            }
        }

        public async Task GenerateKeyConfigurationAsync(string key, byte[] salt)
        {
            // Key configuration is now managed externally - this is a no-op for compatibility
            await Task.CompletedTask;
        }

        public async Task<KeyConfig> GetKeyConfigAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = await connection.QueryFirstOrDefaultAsync<KeyConfig>(
                        "SELECT id, encryptionkey, saltbytes FROM tpm_keyconfig WHERE active = 1",
                        commandType: CommandType.Text);
                    return result ?? new KeyConfig();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetKeyConfigAsync: {ex.Message}");
                throw;
            }
        }
        #endregion

        // EmailServiceLookup methods removed - now handled by static data in AppService
        // Services defined in CommonUtils.Services enum: O365=1, Mailkit=2, ExchangeServer=3, SendGrid=4

        #region AppLookup
        public async Task<string> SaveUpdateEntityAsync(AppLookup Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@appcode", Data.Id == 0 ? null : Data.Id, DbType.Int32, ParameterDirection.InputOutput);
                parameters.Add("@appname", Data.AppName.Trim());
                parameters.Add("@appdesc", Data.Description);
                // Pass Guid directly - DB column is now UNIQUEIDENTIFIER
                parameters.Add("@appclient", Data.AppClient == Guid.Empty ? (Guid?)null : Data.AppClient);
                parameters.Add("@appsecret", Data.AppSecret);
                parameters.Add("@isencrypted", Data.IsEncrypted);
                parameters.Add("@tenantid", null);
                parameters.Add("@userid", Data.UserId);
                parameters.Add("@appowner", Data.AppOwner);
                parameters.Add("@owneremail", Data.OwnerEmail);
                parameters.Add("@fromemailaddress", Data.FromEmailAddress);
                parameters.Add("@fromdisplayname", Data.FromEmailDisplayName);
                parameters.Add("@emailserver", Data.EmailServer);
                // Port is stored as encrypted string
                parameters.Add("@port", Data.EncryptedPort);
                parameters.Add("@emailserviceid", Data.EmailServiceId);
                parameters.Add("@isinternalapp", Data.IsInternalApp);
                parameters.Add("@active", Data.Active);
                parameters.Add("@modifiedby", Data.Id == 0 ? Data.CreatedBy : Data.ModifiedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    // Stored procedure uses OUTPUT parameter for appcode
                    await connection.ExecuteAsync(StoredProcedureNames.CommitApplication,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);

                    int insertedAppCode = parameters.Get<int>("@appcode");
                    return insertedAppCode.ToString();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveUpdateEntityAsync(AppLookup): {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppLookup>> FindApplicationLookupAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = (await connection.QueryAsync<AppLookup>(StoredProcedureNames.SelectApplication,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindApplicationLookupAsync: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Fetches applications with database-level pagination and filtering.
        /// All filtering and pagination is performed at the database level - no in-memory processing.
        /// </summary>
        /// <param name="pageIndex">Page number (1-based)</param>
        /// <param name="pageSize">Number of records per page</param>
        /// <param name="searchTerm">Unified search term - searches across: appname, appowner, owneremail</param>
        /// <param name="userId">Filter by owner user ID</param>
        /// <param name="active">Filter by active status (null = all)</param>
        public async Task<IList<AppLookup>> FindApplicationLookupAsync(int pageIndex, int pageSize, string? searchTerm = null, string? userId = null, bool? active = null)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@pageindex", pageIndex);
                parameters.Add("@pagesize", pageSize);
                parameters.Add("@searchterm", string.IsNullOrWhiteSpace(searchTerm) ? null : searchTerm);
                parameters.Add("@userid", string.IsNullOrWhiteSpace(userId) ? null : Guid.Parse(userId));
                parameters.Add("@active", active);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = (await connection.QueryAsync<AppLookup>(StoredProcedureNames.SelectApplication,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindApplicationLookupAsync (paginated): {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets application count with filters - executed at database level.
        /// Returns total, active, and inactive counts.
        /// </summary>
        public async Task<ApplicationCountDto> GetApplicationCountAsync(string? searchTerm = null, string? userId = null, bool? active = null)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@searchterm", string.IsNullOrWhiteSpace(searchTerm) ? null : searchTerm);
                parameters.Add("@userid", string.IsNullOrWhiteSpace(userId) ? null : Guid.Parse(userId));
                parameters.Add("@active", active);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = await connection.QueryFirstOrDefaultAsync<ApplicationCountDto>(
                        StoredProcedureNames.SelectApplicationCount,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                    
                    return result ?? new ApplicationCountDto();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetApplicationCountAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<AppLookup> FindApplicationAsync(int id)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@appcode", id);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.QuerySingleOrDefaultAsync<AppLookup>(StoredProcedureNames.SelectApplication,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindApplicationAsync(id={id}): {ex.Message}");
                throw;
            }
        }

        public async Task<AppLookup> FindApplicationAsync(Guid id)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@appclient", id, DbType.Guid);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = await connection.QueryFirstOrDefaultAsync<AppLookup>(
                        StoredProcedureNames.SelectApplication,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                    return result;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindApplicationAsync(Guid={id}): {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateApplicationApprovalAsync(int AppId)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@appcode", AppId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitApproveApp, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UpdateApplicationApprovalAsync(AppId={AppId}): {ex.Message}");
                throw;
            }
        }

        public async Task<int> GetAppCountAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.QueryFirstAsync<int>(StoredProcedureNames.SelectAppCount, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetAppCountAsync: {ex.Message}");
                throw;
            }
        }
        #endregion

        #region Log
        public async Task<int> LogAsync(ActivityLog Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                using (var connection = m_dapperContext.CreateConnection())
                {
                    parameters.Add("@logtypeid", Convert.ToInt32(Data.LogTypeLookupId));
                    parameters.Add("@action", Data.Description);
                    parameters.Add("@requestpath", Data.Url);
                    parameters.Add("@createdby", Data.LoggedBy);

                    return await connection.ExecuteAsync(StoredProcedureNames.CommitActivityLog, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in LogAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> AppLoginAsync(AppLogin Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                using (var connection = m_dapperContext.CreateConnection())
                {
                    parameters.Add("@userid", Data.UserId);
                    parameters.Add("@email", Data.Email);
                    parameters.Add("@ipaddress", Data.IPAddress);
                    parameters.Add("@success", Data.Success);

                    return await connection.ExecuteAsync(StoredProcedureNames.CommitLoginAudit, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in AppLoginAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IEnumerable<ActivityLog>> GetAllAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<ActivityLog>(StoredProcedureNames.SelectActivityLog, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetAllAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> SaveAsync(ErrorLog Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                using (var connection = m_dapperContext.CreateConnection())
                {
                    parameters.Add("@errormessage", Data.Error);
                    parameters.Add("@source", Data.ErrorSource);
                    parameters.Add("@createdby", Data.LoggedBy);

                    return await connection.ExecuteAsync(StoredProcedureNames.CommitErrorLog,
                        parameters,
                        commandType: CommandType.StoredProcedure);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveAsync: {ex.Message}");
                throw;
            }
        }
        #endregion

        #region User
        public async Task<Guid> SaveAppUserAsync(AppUser Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@email", Data.Email);
                parameters.Add("@emailblindindex", Data.EmailBlindIndex);
                parameters.Add("@upn", Data.Upn);
                parameters.Add("@username", Data.Username);
                parameters.Add("@appsecret", Data.AppSecret);
                parameters.Add("@salt", Data.Salt);
                parameters.Add("@encryptionkey", Data.EncryptionKey);
                parameters.Add("@appcode", Data.AppCode);
                parameters.Add("@active", Data.Active);
                parameters.Add("@modifiedby", Data.CreatedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<Guid>(StoredProcedureNames.CommitUser, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveAppUserAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> SaveUserRoleAsync(AppUserRole Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", Data.UserId);
                parameters.Add("@roleid", Data.RoleId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitUserRole, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveUserRoleAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateUserRoleAsync(Guid userId, int newRoleId, string modifiedBy)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", userId);
                parameters.Add("@newroleid", newRoleId);
                parameters.Add("@modifiedby", modifiedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.UpdateUserRole, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UpdateUserRoleAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateToVerifiedUserAsync(Guid UserId)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", UserId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitVerifyUser, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UpdateToVerifiedUserAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> UpdateAppUserCredentialsAsync(AppUser Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", Data.UserId);
                parameters.Add("@appsecret", Data.AppSecret);
                parameters.Add("@salt", Data.Salt);
                parameters.Add("@encryptionkey", Data.EncryptionKey);
                parameters.Add("@modifiedby", Data.ModifiedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitUpdateSecret, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in UpdateAppUserCredentialsAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> AppSecreteUpdateLogAsync(AppUser Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", Data.UserId);
                parameters.Add("@modifiedby", Data.ModifiedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitUpdateSecret, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in AppSecreteUpdateLogAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> SaveAppUserCredentialsLogAsync(PasswordUpdate Data)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();

                parameters.Add("@userid", Data.UserId);
                parameters.Add("@noofupdate", Data.NoOfUpdate);
                parameters.Add("@createdby", Data.CreatedBy);
                parameters.Add("@modifiedby", Data.ModifiedBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.ExecuteScalarAsync<int>(StoredProcedureNames.CommitSecretLog, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in SaveAppUserCredentialsLogAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppUserGetDto>> FindAppUsersAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    IList<AppUserGetDto> userList = (await connection.QueryAsync<AppUserGetDto>(StoredProcedureNames.SelectUser,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();

                    foreach (var user in userList)
                    {
                        user.Roles = await FindAppUserRoleAsync(user.UserId);
                    }

                    return userList;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppUsersAsync: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Fetches users with database-level pagination and filtering.
        /// All filtering and pagination is performed at the database level - no in-memory processing.
        /// </summary>
        /// <param name="pageIndex">Page number (1-based)</param>
        /// <param name="pageSize">Number of records per page</param>
        /// <param name="searchTerm">Unified search term - searches across: username, upn, email</param>
        /// <param name="active">Filter by active status (null = all)</param>
        /// <param name="roleId">Filter by role ID (null = all)</param>
        /// <param name="sortBy">Sort option: date_desc, date_asc, name_asc, name_desc</param>
        public async Task<IList<AppUserGetDto>> FindAppUsersAsync(int pageIndex, int pageSize, string? searchTerm = null, bool? active = null, int? roleId = null, string? sortBy = null)
        {
            try
            {
                Console.WriteLine($"[AppRepository.FindAppUsersAsync] START - pageIndex={pageIndex}, pageSize={pageSize}, searchTerm={searchTerm}, active={active}, roleId={roleId}, sortBy={sortBy}");
                
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@pageindex", pageIndex);
                parameters.Add("@pagesize", pageSize);
                parameters.Add("@searchterm", string.IsNullOrWhiteSpace(searchTerm) ? null : searchTerm);
                parameters.Add("@active", active);
                parameters.Add("@roleid", roleId);
                parameters.Add("@sortby", string.IsNullOrWhiteSpace(sortBy) ? null : sortBy);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    IList<AppUserGetDto> userList = (await connection.QueryAsync<AppUserGetDto>(
                        StoredProcedureNames.SelectUser,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();

                    // Fetch roles for each user (this is a small operation per page)
                    foreach (var user in userList)
                    {
                        user.Roles = await FindAppUserRoleAsync(user.UserId);
                    }

                    Console.WriteLine($"[AppRepository.FindAppUsersAsync] SUCCESS - Found {userList.Count} users (page {pageIndex})");
                    return userList;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AppRepository.FindAppUsersAsync] ERROR: {ex.Message}");
                _logger.Error(ex, $"Error in FindAppUsersAsync (paginated): {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets user count with filters - executed at database level.
        /// Returns total, active, and inactive counts.
        /// </summary>
        public async Task<UserCountDto> GetUserCountAsync(string? searchTerm = null, bool? active = null, int? roleId = null)
        {
            try
            {
                Console.WriteLine($"[AppRepository.GetUserCountAsync] START - searchTerm={searchTerm}, active={active}, roleId={roleId}");
                
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@searchterm", string.IsNullOrWhiteSpace(searchTerm) ? null : searchTerm);
                parameters.Add("@active", active);
                parameters.Add("@roleid", roleId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var result = await connection.QueryFirstOrDefaultAsync<UserCountDto>(
                        StoredProcedureNames.SelectUserCount,
                        parameters,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                    
                    Console.WriteLine($"[AppRepository.GetUserCountAsync] SUCCESS - TotalCount={result?.TotalCount}");
                    return result ?? new UserCountDto();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AppRepository.GetUserCountAsync] ERROR: {ex.Message}");
                _logger.Error(ex, $"Error in GetUserCountAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<AppUserGetDto?> FindAppUserByEmailAsync(string Email)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@emailblindindex", Email);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var appUser = await connection.QuerySingleOrDefaultAsync<AppUserGetDto>(
                        StoredProcedureNames.SelectUser, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);

                    if (appUser != null)
                    {
                        appUser.Roles = await FindAppUserRoleAsync(appUser.UserId);
                        appUser.Applications = await FindUserApplicationAsync(appUser.UserId.ToString());
                    }

                    return appUser;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppUserByEmailAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<AppUserGetDto?> FindAppUserByUpnAsync(string upn)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@upn", upn);
                // Don't filter by active status - let the caller check active status
                // This allows finding inactive users for proper error messaging

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var appUser = await connection.QuerySingleOrDefaultAsync<AppUserGetDto>(
                        StoredProcedureNames.SelectUser, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);

                    if (appUser != null)
                    {
                        appUser.Roles = await FindAppUserRoleAsync(appUser.UserId);
                        appUser.Applications = await FindUserApplicationAsync(appUser.UserId.ToString());
                    }

                    return appUser;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppUserByUpnAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<AppUserGetDto?> FindAppUserByIdAsync(string UserId)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@userid", UserId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    var appUser = await connection.QuerySingleOrDefaultAsync<AppUserGetDto>(
                        StoredProcedureNames.SelectUser, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);

                    if (appUser != null)
                    {
                        appUser.Roles = await FindAppUserRoleAsync(appUser.UserId);
                        appUser.Applications = await FindUserApplicationAsync(appUser.UserId.ToString());
                    }

                    return appUser;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppUserByIdAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<int> GetAppUserCountAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return await connection.QueryFirstAsync<int>(StoredProcedureNames.SelectUserCount, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in GetAppUserCountAsync: {ex.Message}");
                throw;
            }
        }

        private async Task<IList<ApplicationGetDto>> FindUserApplicationAsync(string UserId)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@userid", UserId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<ApplicationGetDto>(
                        StoredProcedureNames.SelectUserApplication, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindUserApplicationAsync: {ex.Message}");
                throw;
            }
        }

        private async Task<IList<AppUserRoleDto>> FindAppUserRoleAsync(Guid UserId)
        {
            try
            {
                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@userid", UserId);

                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<AppUserRoleDto>(
                        StoredProcedureNames.SelectUserRole, parameters, commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppUserRoleAsync: {ex.Message}");
                throw;
            }
        }

        public async Task<IList<AppRole>> FindAppRoleAsync()
        {
            try
            {
                using (var connection = m_dapperContext.CreateConnection())
                {
                    return (await connection.QueryAsync<AppRole>(StoredProcedureNames.SelectRole,
                        commandType: CommandType.StoredProcedure)
                        .ConfigureAwait(false))
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Error in FindAppRoleAsync: {ex.Message}");
                throw;
            }
        }
        #endregion
    }
}
