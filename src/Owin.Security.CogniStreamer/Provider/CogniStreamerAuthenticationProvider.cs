using System;
using System.Threading.Tasks;

namespace Owin.Security.CogniStreamer.Provider
{
    /// <summary>
    /// Default <see cref="ICogniStreamerAuthenticationProvider"/> implementation.
    /// </summary>
    public class CogniStreamerAuthenticationProvider : ICogniStreamerAuthenticationProvider
    {
        public CogniStreamerAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
            this.OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<CogniStreamerAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<CogniStreamerReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<CogniStreamerApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever CogniStreamer successfully authenticates a user.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(CogniStreamerAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">Contains information about the redirect request.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(CogniStreamerReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the CogniStreamer middleware.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
        public virtual void ApplyRedirect(CogniStreamerApplyRedirectContext context)
        {
            this.OnApplyRedirect(context);
        }
    }
}
