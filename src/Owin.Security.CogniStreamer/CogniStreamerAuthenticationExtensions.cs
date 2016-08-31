using System;
using Owin.Security.CogniStreamer;

namespace Owin
{
    public static class CogniStreamerAuthenticationExtensions
    {
        public static IAppBuilder UseCogniStreamerAuthentication(this IAppBuilder app, CogniStreamerAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            app.Use<CogniStreamerAuthenticationMiddleware>(app, options);

            return app;
        }

        public static IAppBuilder UseCogniStreamerAuthentication(this IAppBuilder app, Uri portalBaseUrl, string clientId, string clientSecret)
        {
            return app.UseCogniStreamerAuthentication(new CogniStreamerAuthenticationOptions
            {
                PortalBaseUrl = portalBaseUrl,
                ClientId = clientId,
                ClientSecret = clientSecret,
            });
        }
    }
}
