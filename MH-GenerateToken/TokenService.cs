using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MH_GenerateToken
{
    /// <summary>
    /// The requested certificate is missing from the store or cannot be used for signing.
    /// </summary>
    internal class CertificateException : Exception
    {
        public CertificateException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Generate and Validate Token
    /// </summary>
    internal class TokenService : IDisposable
    {
        /// <summary>
        /// Initialise Token Service
        /// </summary>
        /// <param name="appID"></param>
        /// <param name="endpoint"></param>
        /// <param name="thumbprint"></param>
        /// <exception cref="CertificateException">No usable certificate with this thumbprint.</exception>
        public TokenService(string appID, string endpoint, string thumbprint)
        {
            if (string.IsNullOrWhiteSpace(appID))
                throw new ArgumentNullException(nameof(appID));

            if (string.IsNullOrWhiteSpace(endpoint))
                throw new ArgumentNullException(nameof(endpoint));

            if (string.IsNullOrWhiteSpace(thumbprint))
                throw new ArgumentNullException(nameof(thumbprint));

            AppId = appID;
            EndPoint = endpoint;
            ExpiryMinutes = 60;
            X509Cert = FindCertificate(thumbprint);

            // ... Key to Validate JWT. Its key id is the thumbprint, matching the kid/x5t header on the token.
            PublicKey = new X509SecurityKey(X509Cert);
        }

        /// <summary>
        /// Generate JWT
        /// </summary>
        /// <returns></returns>
        internal string GenerateToken()
        {
            // ... Build ClaimSet
            var claims = new ClaimsIdentity(new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, AppId)
            });

            // ... Build Token Descriptor
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Audience = EndPoint,
                Issuer = AppId,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(ExpiryMinutes),
                SigningCredentials = new X509SigningCredentials(X509Cert)
            };

            // ... Build JWT Token
            return new JsonWebTokenHandler().CreateToken(securityTokenDescriptor);
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

            // ... Token Validation
            var tokenValidation = new TokenValidationParameters
            {
                ValidAudience = EndPoint,
                ValidIssuer = AppId,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                IssuerSigningKey = PublicKey
            };

            // JsonWebTokenHandler reports failure through the result; it does not throw.
            return new JsonWebTokenHandler().ValidateToken(token, tokenValidation).IsValid;
        }

        /// <summary>
        /// Releases the certificate.
        /// </summary>
        public void Dispose()
        {
            X509Cert?.Dispose();
        }

        /// <summary>
        /// Find a certificate with a private key in the current user's personal store.
        /// </summary>
        private static X509Certificate2 FindCertificate(string thumbprint)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (matches.Count == 0)
                    throw new CertificateException("No Certificate Found.");

                var certificate = matches[0];
                if (!certificate.HasPrivateKey)
                {
                    certificate.Dispose();
                    throw new CertificateException("The certificate does not have a private key.");
                }

                return certificate;
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
        /// Minutes for token to expire
        /// </summary>
        private double ExpiryMinutes { get; }

        /// <summary>
        /// X509 Certificate to sign JWT
        /// </summary>
        private X509Certificate2 X509Cert { get; }

        /// <summary>
        /// Certificate key to Validate JWT
        /// </summary>
        private X509SecurityKey PublicKey { get; }

        #endregion
    }
}
