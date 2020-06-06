using System;
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
            #region Query Strings

            log.LogInformation("Generating Payload from query strings.");

            string appID = jwtReq.Query["appID"];
            string endpoint = jwtReq.Query["endpoint"];
            string thumbprint = jwtReq.Query["thumbprint"];

            #endregion

            #region Check for missing values

            if (appID == null || thumbprint == null || endpoint == null)
                return new BadRequestObjectResult("Please pass required data in the query string.");

            #endregion

            #region Initialise Token Service

            // ... Initialise JWT Service
            TokenService service;
            try
            {
                service = new TokenService(appID, endpoint, thumbprint);
                log.LogInformation("Successfully initialised token service.");
            }
            catch (Exception ex)
            {
                log.LogInformation("Failed to initialise token service.");
                return new OkObjectResult("Failed to initialise token service, encountered error: " + ex.Message);
            }

            #endregion

            #region Generate Token

            // ... Generate JWT Token
            string generatedToken;
            try
            {
                generatedToken = service.GenerateToken();
                log.LogInformation("Token has been generated.");
            }
            catch (Exception ex)
            {
                log.LogInformation("Failed to generate token.");
                return new OkObjectResult("Unable to generate token, encountered error: " + ex.Message);
            }

            #endregion

            #region Validate Token

            // ... Validate JWT Token
            bool IsValid;
            try
            {
                IsValid = service.ValidateJWT(generatedToken);
            }
            catch (Exception ex)
            {
                return new OkObjectResult("Unable to validate token, encountered error: " + ex.Message);
            }

            log.LogInformation("Token validation has been " + $"{(IsValid ? "successful." : "unsuccessful.")}");

            #endregion

            #region Parse token to JSON Object

            // ... Parsing to JSON Object
            string jsonResponse = null;
            try
            {
                if (IsValid)
                {
                    jsonResponse = JsonConvert.SerializeObject(new { token = generatedToken });
                    log.LogInformation("Serializing token string to a JSON object.");
                }
            }
            catch (Exception ex)
            {
                log.LogInformation("Failed to serialize token.");
                return new OkObjectResult("Unable to serialize token, encountered error: " + ex.Message);
            }

            #endregion

            #region Return Token Response

            return IsValid ?
                (ActionResult)new OkObjectResult(jsonResponse)
                : new BadRequestObjectResult("Invalid Token Generated.");

            #endregion
        }
    }
}