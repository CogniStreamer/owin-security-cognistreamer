using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.CogniStreamer.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class CogniStreamerAuthenticatedContext : BaseContext<CogniStreamerAuthenticationOptions>
    {
        public CogniStreamerAuthenticatedContext(IOwinContext context, CogniStreamerAuthenticationOptions options,
            JObject user, string accessToken, string expires)
            : base(context, options)
        {
            this.User = user;
            this.AccessToken = accessToken;

            int expiresValue;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
                this.ExpiresIn = TimeSpan.FromSeconds(expiresValue);

            var id = this.TryGetValue(user, "id");
            if (id != null) this.Id = Guid.Parse(id);
            this.Username = this.TryGetValue(user, "username");
            this.FirstName = this.TryGetValue(user, "firstName");
            this.LastName = this.TryGetValue(user, "lastName");
            this.Email = this.TryGetValue(user, "email");
        }

        /// <summary>
        /// Gets the JSON-serialized user.
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer access token.
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer access token expiration time.
        /// </summary>
        public TimeSpan? ExpiresIn { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer user's Id.
        /// </summary>
        public Guid? Id { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer user's Username. This value is not always available.
        /// </summary>
        public string Username { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer user's FirstName.
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer user's LastName.
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the CogniStreamer user's Email address.
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user.
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties.
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private string TryGetValue(JObject obj, string propertyName)
        {
            JToken value;
            return obj.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
