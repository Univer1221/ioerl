using System;
using System.Collections.Generic;
using System.IO;

namespace TPEmail.Common.EmailTemplates
{
    public abstract class EmailTemplateBase
    {
        public abstract string GetHtml();

        protected string RenderTemplate(string templateFileName, IReadOnlyDictionary<string, string?> tokens)
        {
            return EmailTemplateRenderer.RenderTemplate(templateFileName, tokens);
        }

        protected Dictionary<string, string?> CreateBaseTokens(string headerTitle)
        {
            return EmailTemplateRenderer.CreateBaseTokens(headerTitle);
        }
    }

    internal static class EmailTemplateRenderer
    {
        private static string? TemplatesRootCache;

        internal static string RenderTemplate(string templateFileName, IReadOnlyDictionary<string, string?> tokens)
        {
            var templateContent = LoadTemplateContent(templateFileName);

            foreach (var token in tokens)
            {
                var placeholder = "{{" + token.Key + "}}";
                templateContent = templateContent.Replace(placeholder, token.Value ?? string.Empty, StringComparison.Ordinal);
            }

            return templateContent;
        }

        internal static Dictionary<string, string?> CreateBaseTokens(string headerTitle)
        {
            return new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["HeaderTitle"] = headerTitle,
                ["Year"] = DateTime.Now.Year.ToString()
            };
        }

        private static string LoadTemplateContent(string templateFileName)
        {
            var templatesRoot = ResolveTemplatesRoot();
            var templatePath = Path.Combine(templatesRoot, templateFileName);

            if (!File.Exists(templatePath))
            {
                throw new FileNotFoundException($"Email template not found: {templatePath}");
            }

            return File.ReadAllText(templatePath);
        }

        private static string ResolveTemplatesRoot()
        {
            if (!string.IsNullOrEmpty(TemplatesRootCache))
            {
                return TemplatesRootCache;
            }

            // First, try checking in the directory structure relative to executing assembly
            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "EmailTemplates", "email"),
                Path.Combine(AppContext.BaseDirectory, "TPEmail.Common", "EmailTemplates", "email"),
                Path.Combine(Directory.GetCurrentDirectory(), "EmailTemplates", "email"),
                Path.Combine(Directory.GetCurrentDirectory(), "TPEmail.Common", "EmailTemplates", "email")
            };

            foreach (var candidate in candidates)
            {
                if (Directory.Exists(candidate))
                {
                    TemplatesRootCache = candidate;
                    return candidate;
                }
            }

            // If not found, walk up the directory tree from BaseDirectory
            var searchRoot = new DirectoryInfo(AppContext.BaseDirectory);
            var maxDepth = 10; // Prevent infinite loops
            var depth = 0;

            while (searchRoot != null && depth < maxDepth)
            {
                // Check for TPEmail.Common\EmailTemplates\email first (most likely in solution structure)
                var commonEmailTemplates = Path.Combine(searchRoot.FullName, "TPEmail.Common", "EmailTemplates", "email");
                if (Directory.Exists(commonEmailTemplates))
                {
                    TemplatesRootCache = commonEmailTemplates;
                    return commonEmailTemplates;
                }

                // Then check for EmailTemplates\email at root level
                var localEmailTemplates = Path.Combine(searchRoot.FullName, "EmailTemplates", "email");
                if (Directory.Exists(localEmailTemplates))
                {
                    TemplatesRootCache = localEmailTemplates;
                    return localEmailTemplates;
                }

                searchRoot = searchRoot.Parent;
                depth++;
            }

            throw new DirectoryNotFoundException(
                $"Email templates directory not found. Searched from: {AppContext.BaseDirectory}. " +
                $"Expected to find: 'TPEmail.Common\\EmailTemplates\\email' or 'EmailTemplates\\email'");
        }
    }

    public static class EmailTemplateFactory
    {
        public static string CreateWelcomeEmail(string userEmail, string appSecret, string? username = null)
        {
            var template = new WelcomeEmailTemplate(userEmail, appSecret, username);
            return template.GetHtml();
        }

        public static string CreateApplicationGuidanceEmail(
            string appName,
            string appOwner,
            string ownerEmail,
            string appClientId,
            string appSecret,
            string fromEmailAddress,
            string baseUrl,
            bool isTPServices = false)
        {
            var template = new ApplicationGuidanceTemplate(
                appName,
                appOwner,
                ownerEmail,
                appClientId,
                appSecret,
                fromEmailAddress,
                baseUrl,
                isTPServices);
            return template.GetHtml();
        }

        public static string CreatePasswordResetEmail(string userEmail, string resetLink, int expiryMinutes = 30)
        {
            var template = new PasswordResetTemplate(userEmail, resetLink, expiryMinutes);
            return template.GetHtml();
        }

        public static string CreateNotificationEmail(string title, string message, string? actionButtonText = null, string? actionButtonUrl = null)
        {
            var template = new NotificationEmailTemplate(title, message, actionButtonText, actionButtonUrl);
            return template.GetHtml();
        }
    }

    public class WelcomeEmailTemplate : EmailTemplateBase
    {
        public string UserEmail { get; set; }
        public string AppSecret { get; set; }
        public string Username { get; set; }

        public WelcomeEmailTemplate(string userEmail, string appSecret, string? username = null)
        {
            UserEmail = userEmail;
            AppSecret = appSecret;
            Username = username ?? userEmail;
        }

        public override string GetHtml()
        {
            var tokens = CreateBaseTokens("Welcome to TPMailer");
            tokens["Username"] = Username;
            tokens["UserEmail"] = UserEmail;
            tokens["AppSecret"] = AppSecret;

            return RenderTemplate("WelcomeEmailTemplate.cshtml", tokens);
        }
    }

    public class PasswordResetTemplate : EmailTemplateBase
    {
        public string UserEmail { get; set; }
        public string ResetLink { get; set; }
        public int ExpiryMinutes { get; set; }

        public PasswordResetTemplate(string userEmail, string resetLink, int expiryMinutes = 30)
        {
            UserEmail = userEmail;
            ResetLink = resetLink;
            ExpiryMinutes = expiryMinutes;
        }

        public override string GetHtml()
        {
            var tokens = CreateBaseTokens("Password Reset Request");
            tokens["UserEmail"] = UserEmail;
            tokens["ResetLink"] = ResetLink;
            tokens["ExpiryMinutes"] = ExpiryMinutes.ToString();

            return RenderTemplate("PasswordResetTemplate.cshtml", tokens);
        }
    }

    public class NotificationEmailTemplate : EmailTemplateBase
    {
        public string Title { get; set; }
        public string Message { get; set; }
        public string? ActionButtonText { get; set; }
        public string? ActionButtonUrl { get; set; }

        public NotificationEmailTemplate(string title, string message, string? actionButtonText = null, string? actionButtonUrl = null)
        {
            Title = title;
            Message = message;
            ActionButtonText = actionButtonText;
            ActionButtonUrl = actionButtonUrl;
        }

        public override string GetHtml()
        {
            var tokens = CreateBaseTokens(Title);
            tokens["Title"] = Title;
            tokens["Message"] = Message;
            tokens["ActionButtonText"] = ActionButtonText ?? string.Empty;
            tokens["ActionButtonUrl"] = ActionButtonUrl ?? string.Empty;

            var templateName = !string.IsNullOrEmpty(ActionButtonText) && !string.IsNullOrEmpty(ActionButtonUrl)
                ? "NotificationEmailTemplate.WithButton.cshtml"
                : "NotificationEmailTemplate.NoButton.cshtml";

            return RenderTemplate(templateName, tokens);
        }
    }

    public class ApplicationGuidanceTemplate : EmailTemplateBase
    {
        public string AppName { get; set; }
        public string AppOwner { get; set; }
        public string OwnerEmail { get; set; }
        public string AppClientId { get; set; }
        public string AppSecret { get; set; }
        public string FromEmailAddress { get; set; }
        public string BaseUrl { get; set; }
        public bool IsTPServices { get; set; }

        public ApplicationGuidanceTemplate(
            string appName,
            string appOwner,
            string ownerEmail,
            string appClientId,
            string appSecret,
            string fromEmailAddress,
            string baseUrl,
            bool isTPServices = false)
        {
            AppName = appName;
            AppOwner = appOwner;
            OwnerEmail = ownerEmail;
            AppClientId = appClientId;
            AppSecret = appSecret;
            FromEmailAddress = fromEmailAddress;
            BaseUrl = baseUrl?.TrimEnd('/') ?? string.Empty;
            IsTPServices = isTPServices;
        }

        public override string GetHtml()
        {
            var tokens = CreateBaseTokens("Application Registration Successful");
            tokens["AppName"] = AppName;
            tokens["AppOwner"] = AppOwner;
            tokens["AppClientId"] = AppClientId;
            tokens["AppSecret"] = AppSecret;
            tokens["FromEmailAddress"] = FromEmailAddress;
            tokens["BaseUrl"] = BaseUrl;
            tokens["SmtpType"] = IsTPServices ? "TP Services (Managed)" : "External SMTP (Your Server)";

            var templateName = IsTPServices
                ? "ApplicationGuidanceTemplate.TPServices.cshtml"
                : "ApplicationGuidanceTemplate.External.cshtml";

            return RenderTemplate(templateName, tokens);
        }
    }
}
