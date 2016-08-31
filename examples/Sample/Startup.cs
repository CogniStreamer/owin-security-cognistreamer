using System;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.CogniStreamer;

[assembly: OwinStartup(typeof(Sample.Startup))]

namespace Sample
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var configuration = new HttpConfiguration();
            configuration.MapHttpAttributeRoutes();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                CookieHttpOnly = true,
                CookieSecure = CookieSecureOption.SameAsRequest,
                ExpireTimeSpan = TimeSpan.FromDays(1),
                SlidingExpiration = false
            });

            app.UseCogniStreamerAuthentication(new CogniStreamerAuthenticationOptions
            {
                ClientId = "LoginProviderTest",
                ClientSecret = "S3cr3t",
                PortalBaseUrl = new Uri("http://localhost:8351/"),
                AuthenticationMode = AuthenticationMode.Active,
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
            });

            app.UseWebApi(configuration);
        }
    }
}
