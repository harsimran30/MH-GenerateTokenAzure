using System;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace MH_GenerateToken
{
    public static class GenerateToken
    {
        [FunctionName("GenerateToken")]
        public static IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest jwtReq,
            ILogger log)
        {
            string appID = jwtReq.Query["appID"];
            string endpoint = jwtReq.Query["endpoint"];
            string thumbprint = jwtReq.Query["thumbprint"];

            if (string.IsNullOrWhiteSpace(appID) || string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(thumbprint))
                return new BadRequestObjectResult("Please pass appID, endpoint and thumbprint in the query string.");

            // Thumbprints copied from the certificate manager often contain spaces or hidden characters.
            thumbprint = Regex.Replace(thumbprint, "[^0-9a-fA-F]", string.Empty);

            try
            {
                using (var service = new TokenService(appID, endpoint, thumbprint))
                {
                    string generatedToken = service.GenerateToken();
                    log.LogInformation("Token has been generated.");

                    bool isValid = service.ValidateJWT(generatedToken);
                    log.LogInformation("Token validation has been " + $"{(isValid ? "successful." : "unsuccessful.")}");

                    if (!isValid)
                        return new BadRequestObjectResult("Invalid Token Generated.");

                    return new ContentResult
                    {
                        Content = JsonConvert.SerializeObject(new { token = generatedToken }),
                        ContentType = "application/json",
                        StatusCode = StatusCodes.Status200OK
                    };
                }
            }
            catch (CertificateException ex)
            {
                log.LogWarning(ex.Message);
                return new BadRequestObjectResult(ex.Message);
            }
            catch (Exception ex)
            {
                // Details go to the log only; callers get a failure status instead of a 200 with an error string.
                log.LogError(ex, "Failed to generate token.");
                return new ObjectResult("Unable to generate token.") { StatusCode = StatusCodes.Status500InternalServerError };
            }
        }
    }
}
