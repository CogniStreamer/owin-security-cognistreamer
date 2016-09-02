using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer
{
    internal class CogniStreamerAuthenticationHandler : AuthenticationHandler<CogniStreamerAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private static readonly PathString AuthorizeEndpoint = new PathString("/oauth2/authorize");
        private static readonly PathString TokenEndpoint = new PathString("/oauth2/token");
        private static readonly PathString SignOutEndpoint = new PathString("/account/logout");
        private static readonly PathString UserInfoEndpoint = new PathString("/api/v1.1/m/profile");

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public CogniStreamerAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IList<string> values = this.Request.Query.GetValues("error");
                if (values != null && values.Any())
                    this.logger.WriteVerbose("Remote server returned an error: " + this.Request.QueryString);

                values = this.Request.Query.GetValues("code");
                if (values != null && values.Count == 1)
                    code = values[0];

                values = this.Request.Query.GetValues("state");
                if (values != null && values.Count == 1)
                    state = values[0];

                properties = this.Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    this.logger.WriteVerbose("Remote server sends corrupt state");
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!this.ValidateCorrelationId(properties, logger))
                    return new AuthenticationTicket(null, properties);

                if (code == null)
                    return new AuthenticationTicket(null, properties);

                string requestPrefix = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host;
                string redirectUri = requestPrefix + this.Request.PathBase + this.Options.CallbackPath;
                var tokenResponse = await this.RequestToken(code, redirectUri);

                var user = await this.RequestUserInfo(tokenResponse.AccessToken);

                var context = new CogniStreamerAuthenticatedContext(this.Context, user, tokenResponse.AccessToken, tokenResponse.ExpiresIn);
                context.Identity = new ClaimsIdentity(this.Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                if (context.Id.HasValue)
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id.Value.ToString(), XmlSchemaString, this.Options.AuthenticationType));

                if (!string.IsNullOrEmpty(context.Username))
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Username, XmlSchemaString, this.Options.AuthenticationType));

                if (!string.IsNullOrEmpty(context.FirstName))
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.FirstName, XmlSchemaString, this.Options.AuthenticationType));

                if (!string.IsNullOrEmpty(context.LastName))
                    context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.LastName, XmlSchemaString, this.Options.AuthenticationType));

                if (!string.IsNullOrEmpty(context.Email))
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));

                context.Properties = properties;

                await this.Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                this.logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401) return Task.FromResult<object>(null);

            var challenge = Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    this.Request.Scheme +
                    Uri.SchemeDelimiter +
                    this.Request.Host +
                    this.Request.PathBase;

                string currentUri =
                    baseUri +
                    this.Request.Path +
                    this.Request.QueryString;

                string redirectUri =
                    baseUri +
                    this.Options.CallbackPath;

                var properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri)) properties.RedirectUri = currentUri;

                // OAuth2 10.12 CSRF
                this.GenerateCorrelationId(properties);

                string scope = string.Join(" ", this.Options.Scope);

                string state = this.Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    new Uri(this.Options.PortalBaseUrl, AuthorizeEndpoint.Value).ToString() +
                    "?response_type=code" +
                    "&client_id=" + Uri.EscapeDataString(this.Options.ClientId) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&scope=" + Uri.EscapeDataString(scope) +
                    "&state=" + Uri.EscapeDataString(state);

                var redirectContext = new CogniStreamerApplyRedirectContext(this.Context, this.Options, properties, authorizationEndpoint);
                this.Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (this.Options.CallbackPath.HasValue && this.Options.CallbackPath == this.Request.Path)
            {
                var ticket = await this.AuthenticateAsync();
                if (ticket == null)
                {
                    this.logger.WriteWarning("Invalid return state, unable to redirect.");
                    this.Response.StatusCode = 500;
                    return true;
                }

                var context = new CogniStreamerReturnEndpointContext(this.Context, ticket);
                context.SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await this.Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    var grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    this.Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // Add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }

                    this.Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }

            return false;
        }

        protected override Task ApplyResponseGrantAsync()
        {
            if (this.Context.Authentication.AuthenticationResponseRevoke != null &&
                this.Context.Authentication.AuthenticationResponseRevoke.AuthenticationTypes.Contains(this.Options.AuthenticationType))
            {
                string redirectUri =
                    this.Request.Scheme +
                    Uri.SchemeDelimiter +
                    this.Request.Host +
                    this.Request.PathBase;

                string signOutEndpoint =
                    new Uri(this.Options.PortalBaseUrl, SignOutEndpoint.Value).ToString() +
                    "?returnurl=" + Uri.EscapeDataString(redirectUri);

                this.Response.Redirect(signOutEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        private async Task<TokenResponse> RequestToken(string code, string redirectUri)
        {
            var tokenRequestContent = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "grant_type", "authorization_code" },
                    { "code", code },
                    { "redirect_uri", redirectUri },
                    { "client_id", this.Options.ClientId },
                    { "client_secret", this.Options.ClientSecret },
                });
            string tokenEndpoint = new Uri(this.Options.PortalBaseUrl, TokenEndpoint.Value).ToString();
            this.httpClient.DefaultRequestHeaders.Accept.Clear();
            this.httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var response = await this.httpClient.PostAsync(tokenEndpoint, tokenRequestContent, this.Request.CallCancelled);
            response.EnsureSuccessStatusCode();
            return JsonConvert.DeserializeObject<TokenResponse>(await response.Content.ReadAsStringAsync());
        }

        private async Task<JObject> RequestUserInfo(string accessToken)
        {
            string userInfoEndpoint = new Uri(this.Options.PortalBaseUrl, UserInfoEndpoint.Value).ToString();
            this.httpClient.DefaultRequestHeaders.Accept.Clear();
            this.httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            this.httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await this.httpClient.GetAsync(userInfoEndpoint, this.Request.CallCancelled);
            response.EnsureSuccessStatusCode();
            var text = await response.Content.ReadAsStringAsync();
            return JObject.Parse(text);
        }

        private class TokenResponse
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("refresh_token")]
            public string RefreshToken { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }

            [JsonProperty("expires_in")]
            public string ExpiresIn { get; set; }
        }
    }
}
