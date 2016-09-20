using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Testing;
using Moq;
using Newtonsoft.Json;
using NUnit.Framework;

namespace Owin.Security.CogniStreamer.Tests
{
    [TestFixture]
    public class CogniStreamerAuthenticationMiddlewareTests
    {
        private CogniStreamerAuthenticationOptions options;

        [SetUp]
        public void SetUp()
        {
            this.options = new CogniStreamerAuthenticationOptions()
            {
                AuthenticationMode = AuthenticationMode.Active,
                PortalBaseUrl = new Uri("https://portalbase.com/"),
                ClientId = "id",
                ClientSecret = "secret",
            };
        }

        [Test]
        public async Task CogniStreamerAuthenticationMiddleware_Testing200And404_ShouldNotRedirect()
        {
            using (var server = this.CreateTestServer(this.options))
            {
                var response = await server.HttpClient.GetAsync("/notfound");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(response.Headers.Location, Is.Null);
                response = await server.HttpClient.GetAsync("/found");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                Assert.That(response.Headers.Location, Is.Null);
            }
        }

        [Test]
        public async Task CogniStreamerAuthenticationMiddleware_Testing401_ShouldRedirectToAuthorizeEndpointWithCorrectQueryParameters()
        {
            using (var server = this.CreateTestServer(this.options))
            {
                var response = await server.HttpClient.GetAsync("/private");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(response.Headers.Location, Is.Not.Null);
                Assert.That(response.Headers.Location.Scheme, Is.EqualTo("https"));
                Assert.That(response.Headers.Location.Host, Is.EqualTo("portalbase.com"));
                Assert.That(response.Headers.Location.AbsolutePath, Is.EqualTo("/oauth2/authorize"));

                Assert.IsFalse(response.Headers.Location.Query.Contains("secret"), "secret revealed!");
                var query = HttpUtility.ParseQueryString(response.Headers.Location.Query);
                Assert.That(query["response_type"], Is.EqualTo("code"));
                Assert.That(query["client_id"], Is.EqualTo("id"));
                Assert.That(query["redirect_uri"], Is.EqualTo("http://localhost/signin-cognistreamer"));
                Assert.That(query["scope"], Is.EqualTo("login profile"));
                Assert.That(query["state"].Length, Is.GreaterThanOrEqualTo(32), "state too small");
            }
        }

        [Test]
        public async Task CogniStreamerAuthenticationMiddleware_CompleteFlow_ShouldAuthenticateUser()
        {
            var notificationsMock = new Mock<IFakePortalNotifications>();
            notificationsMock.Setup(x => x.GenerateToken(It.IsAny<IFormCollection>())).Returns(@"{
                    access_token: 'at789',
                    refresh_token: 'rt456',
                    expires_in: 3600,
                    token_type: 'bearer'
                }");
            notificationsMock.Setup(x => x.GetUserProfile(It.IsAny<string>(), It.IsAny<string>())).Returns(@"{
                    id: 'dcec99ad-28e1-4194-a4e0-f22148963cc5',
                    username: 'cashj',
                    firstName: 'Johnny',
                    lastName: 'Cash',
                    email: 'cashj@walktheline.com'
                }");

            this.options.BackchannelHttpHandler = new FakePortalHttpMessageHandler(notificationsMock.Object);

            using (var server = this.CreateTestServer(this.options))
            {
                // Intercept state and CSRF cookie
                var response = await server.HttpClient.GetAsync("/private");
                var query = HttpUtility.ParseQueryString(response.Headers.Location.Query);
                var state = query["state"];

                using (var client = server.HttpClient)
                {
                    // Forward CSRF cookie
                    foreach (var cookie in response.Headers.GetValues("Set-Cookie"))
                        client.DefaultRequestHeaders.Add("Cookie", cookie);

                    response = await client.GetAsync("/signin-cognistreamer?code=my_code&state=" + state);

                    notificationsMock.Verify(x => x.GenerateToken(It.IsAny<IFormCollection>()), Times.Once);
                    notificationsMock.Verify(x => x.GetUserProfile("Bearer", "at789"), Times.Once);

                    var authenticationCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault(x => x.StartsWith("AUTH="));
                    Assert.That(authenticationCookie, Is.Not.Null);

                    client.DefaultRequestHeaders.Add("Cookie", authenticationCookie);
                    response = await client.GetAsync("/private");
                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

                    var claims = JsonConvert.DeserializeObject<IDictionary<string, string>>(await response.Content.ReadAsStringAsync());
                    Assert.That(claims, Contains.Key(ClaimTypes.NameIdentifier));
                    Assert.That(claims, Contains.Key(ClaimTypes.Name));
                    Assert.That(claims, Contains.Key(ClaimTypes.GivenName));
                    Assert.That(claims, Contains.Key(ClaimTypes.Surname));
                    Assert.That(claims, Contains.Key(ClaimTypes.Email));
                    Assert.That(claims[ClaimTypes.NameIdentifier], Is.EqualTo("dcec99ad-28e1-4194-a4e0-f22148963cc5"));
                    Assert.That(claims[ClaimTypes.Name], Is.EqualTo("cashj"));
                    Assert.That(claims[ClaimTypes.GivenName], Is.EqualTo("Johnny"));
                    Assert.That(claims[ClaimTypes.Surname], Is.EqualTo("Cash"));
                    Assert.That(claims[ClaimTypes.Email], Is.EqualTo("cashj@walktheline.com"));
                }
            }
        }

        [Test]
        public async Task CogniStreamerAuthenticationMiddleware_SignOut_ShouldRedirect()
        {
            using (var server = this.CreateTestServer(this.options))
            {
                var response = await server.HttpClient.GetAsync("/signout");
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(response.Headers.Location, Is.EqualTo(new Uri("https://portalbase.com/logout?returnurl=http:%2F%2Flocalhost")));
            }
        }

        private TestServer CreateTestServer(CogniStreamerAuthenticationOptions options)
        {
            return TestServer.Create(app =>
                {
                    app.UseCookieAuthentication(new CookieAuthenticationOptions
                        {
                            AuthenticationMode = AuthenticationMode.Active,
                            CookieSecure = CookieSecureOption.SameAsRequest,
                            CookieHttpOnly = true,
                            CookieName = "AUTH"
                        });
                    options.SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType;
                    app.UseCogniStreamerAuthentication(options);
                    app.Use(async (ctx, next) =>
                        {
                            if (ctx.Request.Path.Equals(new PathString("/found")))
                            {
                                ctx.Response.StatusCode = 200;
                            }
                            else if (ctx.Request.Path.Equals(new PathString("/private")))
                            {
                                var identity = ctx.Authentication?.User?.Identity as ClaimsIdentity;
                                if (identity != null && identity.IsAuthenticated)
                                {
                                    ctx.Response.StatusCode = 200;
                                    ctx.Response.ContentType = "application/json";
                                    using (var writer = new StreamWriter(ctx.Response.Body))
                                    {
                                        var claims = identity.Claims.ToDictionary(c => c.Type, c => c.Value);
                                        writer.Write(JsonConvert.SerializeObject(claims));
                                    }
                                }
                                else
                                {
                                    ctx.Response.StatusCode = 401;
                                }
                            }
                            else if (ctx.Request.Path.Equals(new PathString("/signout")))
                            {
                                ctx.Authentication.SignOut(CogniStreamerAuthenticationDefaults.AuthenticationType);
                            }
                            else
                            {
                                await next();
                            }
                        });
                });
        }

        public interface IFakePortalNotifications
        {
            string GenerateToken(IFormCollection requestFormBody);
            string GetUserProfile(string authenticationScheme, string accessToken);
        }

        private class FakePortalHttpMessageHandler : HttpMessageHandler
        {
            private readonly IFakePortalNotifications notifications;

            public FakePortalHttpMessageHandler(IFakePortalNotifications notifications)
            {
                this.notifications = notifications;
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var json = string.Empty;

                if (request.Method == HttpMethod.Post && request.RequestUri.AbsoluteUri.Equals("https://portalbase.com/oauth2/token"))
                {
                    var formBody = WebHelpers.ParseForm(await request.Content.ReadAsStringAsync());
                    json = this.notifications.GenerateToken(formBody);
                }
                else if (request.Method == HttpMethod.Get && request.RequestUri.AbsoluteUri.Equals("https://portalbase.com/api/v1.1/m/profile"))
                {
                    json = this.notifications.GetUserProfile(request.Headers.Authorization.Scheme, request.Headers.Authorization.Parameter);
                }

                var response = new HttpResponseMessage(HttpStatusCode.NotFound);
                if (!string.IsNullOrEmpty(json))
                {
                    response.StatusCode = HttpStatusCode.OK;
                    response.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }

                return response;
            }
        }
    }
}
