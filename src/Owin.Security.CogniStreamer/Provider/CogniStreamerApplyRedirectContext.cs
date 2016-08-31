using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.CogniStreamer.Provider
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the CogniStreamer middleware.
    /// </summary>
    public class CogniStreamerApplyRedirectContext : BaseContext<CogniStreamerAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context.</param>
        /// <param name="options">The CogniStreamer middleware options.</param>
        /// <param name="properties">The authenticaiton properties of the challenge.</param>
        /// <param name="redirectUri">The initial redirect URI.</param>
        [SuppressMessage("Microsoft.Design", "CA1054:UriParametersShouldNotBeStrings", MessageId = "3#", Justification = "Represents header value")]
        public CogniStreamerApplyRedirectContext(IOwinContext context, CogniStreamerAuthenticationOptions options,
            AuthenticationProperties properties, string redirectUri)
            : base(context, options)
        {
            this.RedirectUri = redirectUri;
            this.Properties = properties;
        }

        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Justification = "Represents header value")]
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authentication properties of the challenge.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}
