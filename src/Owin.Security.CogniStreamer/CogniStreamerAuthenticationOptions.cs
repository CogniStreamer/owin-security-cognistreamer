using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer
{
    public class CogniStreamerAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to CogniStreamer.
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with CogniStreamer.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with CogniStreamer.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-cognistreamer".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the base url of the CogniStreamer portal to use for authentication.
        /// </summary>
        public Uri PortalBaseUrl { get; set; }

        /// <summary>
        ///     Gets or sets the OAuth2 Client ID.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the OAuth2 Client Secret.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="ICogniStreamerAuthenticationProvider" /> used in the authentication events.
        /// </summary>
        public ICogniStreamerAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public CogniStreamerAuthenticationOptions()
            : base(CogniStreamerAuthenticationDefaults.AuthenticationType)
        {
            Caption = CogniStreamerAuthenticationDefaults.AuthenticationType;
            CallbackPath = new PathString(CogniStreamerAuthenticationDefaults.CallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "login",
                "profile",
            };
            BackchannelTimeout = TimeSpan.FromMinutes(1);
        }
    }
}
