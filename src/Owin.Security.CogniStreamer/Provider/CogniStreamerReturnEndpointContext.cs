using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.CogniStreamer.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class CogniStreamerReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">OWIN environment.</param>
        /// <param name="ticket">The authenticateion ticket.</param>
        public CogniStreamerReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
