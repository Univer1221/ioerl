namespace TPEmail.DataAccess.Service.v1_0
{
    public static class TPAssistService
    {
        private const string API_ENDPOINT = "/api/Analysis/GenerateResponse";

        public static async Task<TPAssistResult> EnhanceEmailAsync(string originalBody, string subject, bool isHtml)
        {
            var baseUrl = Environment.GetEnvironmentVariable("tpassistbaseurl");
            var apiKey = Environment.GetEnvironmentVariable("tpassistapikey");
            var apiSecret = Environment.GetEnvironmentVariable("tpassistapisecret");
            var projectId = Environment.GetEnvironmentVariable("tpassistprojectid") ?? "3090";
            var versionId = Environment.GetEnvironmentVariable("tpassistversionid") ?? "2";
            var flowId = Environment.GetEnvironmentVariable(isHtml ? "tpassistflowidhtml" : "tpassistflowidtext");

            if (string.IsNullOrEmpty(baseUrl) || string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret) || string.IsNullOrEmpty(flowId))
                return new TPAssistResult { Success = false, ErrorMessage = "TPAssist configuration missing. Check environment variables.", Body = originalBody, IsHtml = isHtml };

            if (string.IsNullOrWhiteSpace(originalBody))
                return new TPAssistResult { Success = false, ErrorMessage = "Email body cannot be empty", Body = originalBody, IsHtml = isHtml };

            try
            {
                var formContent = new MultipartFormDataContent
                {
                    { new StringContent($"<EMAIL_TEXT>{originalBody}</EMAIL_TEXT>"), "userInput" },
                    { new StringContent(""), "userContext" },
                    { new StringContent("2"), "userUpn" },
                    { new StringContent(flowId), "flowid" },
                    { new StringContent(projectId), "projectId" },
                    { new StringContent(versionId), "versionId" }
                };

                using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
                httpClient.DefaultRequestHeaders.Add("X-API-KEY", apiKey);
                httpClient.DefaultRequestHeaders.Add("X-API-SECRET", apiSecret);

                var response = await httpClient.PostAsync(baseUrl.TrimEnd('/') + API_ENDPOINT, formContent);
                if (!response.IsSuccessStatusCode)
                    return new TPAssistResult { Success = false, ErrorMessage = $"API error: {response.StatusCode}", Body = originalBody, IsHtml = isHtml };

                var enhancedBody = (await response.Content.ReadAsStringAsync()).Trim();
                return string.IsNullOrWhiteSpace(enhancedBody)
                    ? new TPAssistResult { Success = false, ErrorMessage = "Empty response", Body = originalBody, IsHtml = isHtml }
                    : new TPAssistResult { Success = true, Body = enhancedBody, IsHtml = isHtml };
            }
            catch (TaskCanceledException)
            {
                return new TPAssistResult { Success = false, ErrorMessage = "Request timed out", Body = originalBody, IsHtml = isHtml };
            }
            catch (Exception ex)
            {
                return new TPAssistResult { Success = false, ErrorMessage = ex.Message, Body = originalBody, IsHtml = isHtml };
            }
        }
    }

    public class TPAssistResult
    {
        public bool Success { get; set; }
        public string Body { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
        public bool IsHtml { get; set; }
    }
}
