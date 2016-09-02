using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Moq;
using NUnit.Framework;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer.Tests.Provider
{
    [TestFixture]
    public class CogniStreamerReturnEndpointContextTests
    {
        [Test]
        public void CogniStreamerReturnEndpointContext_PassArgumentsToConstructor_ShouldSetProperties()
        {
            var owinContext = new Mock<IOwinContext>().Object;
            var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, "some.email.address@some.server.com") });
            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
            var context = new CogniStreamerReturnEndpointContext(owinContext, ticket);
            Assert.That(context.OwinContext, Is.EqualTo(owinContext));
            Assert.That(context.Identity, Is.EqualTo(identity));
            Assert.That(context.Identity.HasClaim(ClaimTypes.Email, "some.email.address@some.server.com"));
        }
    }
}
