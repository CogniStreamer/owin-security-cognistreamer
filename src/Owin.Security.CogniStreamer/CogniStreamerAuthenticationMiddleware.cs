using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer
{
    /// <summary>
    /// OWIN middleware for authenticating users using a CogniStreamer portal.
    /// </summary>
    [SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable", Justification = "Middleware is not disposable.")]
    public class CogniStreamerAuthenticationMiddleware : AuthenticationMiddleware<CogniStreamerAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public CogniStreamerAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, CogniStreamerAuthenticationOptions options)
            : base(next, options)
        {
            if (this.Options.PortalBaseUrl == null) throw new ArgumentNullException("PortalBaseUrl option must be provided");
            if (string.IsNullOrWhiteSpace(this.Options.ClientId)) throw new ArgumentException("ClientId option must be provided");
            if (string.IsNullOrWhiteSpace(this.Options.ClientSecret)) throw new ArgumentException("ClientSecret option must be provided");

            this.logger = app.CreateLogger<CogniStreamerAuthenticationMiddleware>();

            if (this.Options.Provider == null) this.Options.Provider = new CogniStreamerAuthenticationProvider();

            if (this.Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(CogniStreamerAuthenticationMiddleware).FullName,
                    this.Options.AuthenticationType, "v1");
                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
                this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            this.httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options))
            {
                Timeout = this.Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10,    // 10 MB
            };
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.GooglePlus.GooglePlusAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<CogniStreamerAuthenticationOptions> CreateHandler()
        {
            return new CogniStreamerAuthenticationHandler(this.httpClient, this.logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(CogniStreamerAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;

            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null) throw new InvalidOperationException("BackchannelHttpHandler is not of the type WebRequestHandler");

            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;
        }
    }
}
