using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MH_GenerateToken
{
    /// <summary>
    /// Generate and Validate Token
    /// </summary>
    internal class TokenService
    {
        /// <summary>
        /// Initialise Token Service
        /// </summary>
        /// <param name="appID"></param>
        /// <param name="endpoint"></param>
        /// <param name="thumbprint"></param>
        public TokenService(string appID, string endpoint, string thumbprint)
        {
            AppId = appID;
            EndPoint = endpoint;
            Thumbprint = thumbprint;
            ExpiryMinutes = 60;
            FetchCertificate();
        }

        /// <summary>
        /// Generate JWT
        /// </summary>
        /// <returns></returns>
        internal string GenerateToken()
        {
            try
            {
                // ... Build ClaimSet
                var claims = new ClaimsIdentity(new Claim[]
                {
                new Claim( JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString() ),
                new Claim( JwtRegisteredClaimNames.Sub, AppId )
                });

                // ... Build Token Descriptor
                var securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claims,
                    Audience = EndPoint,
                    Issuer = AppId,
                    NotBefore = DateTime.Now,
                    Expires = DateTime.Now.AddMinutes(ExpiryMinutes),
                    SigningCredentials = new X509SigningCredentials(X509Cert)
                };

                // ... Build JWT Token
                var handler = new JsonWebTokenHandler();
                return handler.CreateToken(securityTokenDescriptor);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed in Generate JWT, error " + ex.Message);
            }
        }

        /// <summary>
        /// Validate JWT Token
        /// </summary>
        /// <param name="token">Encoded Token</param>
        /// <returns>Return true if generated Token is valid.</returns>
        internal bool ValidateJWT(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");
            try
            {
                // ... Token Validation
                var tokenValidation = new TokenValidationParameters
                {
                    ValidAudience = EndPoint,
                    ValidIssuer = AppId,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    IssuerSigningKey = PublicKey
                };

                try
                {
                    new JsonWebTokenHandler().ValidateToken(token, tokenValidation);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed in Validate Token, error " + ex.Message);
            }
        }

        /// <summary>
        /// Find certificate and set Keys from it
        /// </summary>
        private void FetchCertificate()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                try
                {
                    store.Open(OpenFlags.ReadOnly);

                    var x509Collection = store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, false);
                    if (x509Collection == null || x509Collection.Count == 0)
                        throw new Exception("No Certificate Found.");

                    // ... Set Certificate
                    X509Cert = x509Collection[0];
                }
                finally
                {
                    // ... Public Key to Validate JWT
                    PublicKey = new RsaSecurityKey(X509Cert.GetRSAPublicKey());
                    store.Close();
                }
            }
            catch (Exception ex)
            {
                store.Close();
                throw new Exception("Failed in Fetch Certificates, error " + ex.Message);
            }
        }

        #region Properties

        /// <summary>
        /// Application ID
        /// </summary>
        private string AppId { get; }

        /// <summary>
        /// Endpoint
        /// </summary>
        private string EndPoint { get; }

        /// <summary>
        /// Certificate Thumbprint
        /// </summary>
        private string Thumbprint { get; }

        /// <summary>
        /// Minutes for token to expire
        /// </summary>
        private double ExpiryMinutes { get; }

        /// <summary>
        /// X509 Certificate to sign JWT
        /// </summary>
        private X509Certificate2 X509Cert { get; set; }

        /// <summary>
        /// RSA Public Key from Certificate to Validate JWT
        /// </summary>
        private RsaSecurityKey PublicKey { get; set; }

        #endregion
    }
}