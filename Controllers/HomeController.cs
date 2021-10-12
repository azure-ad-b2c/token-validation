using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using token_validation.Models;

namespace token_validation.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;


        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> IndexAsync()
        {

            string wellKnownConfig = Request.Query["config"];
            string issuer = Request.Query["iss"];
            string audience = Request.Query["aud"];
            string token = Request.Query["token"];

            try
            {
                // Check the query string parameters
                if (string.IsNullOrEmpty(wellKnownConfig)) throw new Exception("The 'config' parameter is missing.");
                if (string.IsNullOrEmpty(issuer)) throw new Exception("The 'iss' parameter is missing.");
                if (string.IsNullOrEmpty(audience)) throw new Exception("The 'aud' parameter is missing.");
                if (string.IsNullOrEmpty(token)) throw new Exception("The 'token' parameter is missing.");

                // Validate the access token
                var validatedToken = await ValidateToken(wellKnownConfig, issuer, audience, token);

                if (validatedToken == null)
                {
                    ViewBag.Message = "Invalid access token";
                }
                else
                {
                    ViewBag.Message = "The access token is valid";
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Message = "ERROR: " + ex.Message;
            }

            return View();

        }

        private async Task<JwtSecurityToken> ValidateToken(string wellKnownConfig, string issuer, string audience, string token)
        {
            // Get the OpenID Connect discovery document
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                wellKnownConfig,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());

            var discoveryDocument = await configurationManager.GetConfigurationAsync(CancellationToken.None);

            // Get the keys
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                // Signature validation
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,

                // Issuer validation
                ValidateIssuer = true,
                ValidIssuer = issuer,

                // Audience validation
                ValidateAudience = true,
                ValidAudience = audience,

                // Expiration validation
                RequireExpirationTime = true,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.FromMinutes(2),
            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException)
            {
                throw;
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
