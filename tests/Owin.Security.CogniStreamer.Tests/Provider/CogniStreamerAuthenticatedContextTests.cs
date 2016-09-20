using System;
using Microsoft.Owin;
using Moq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer.Tests.Provider
{
    [TestFixture]
    public class CogniStreamerAuthenticatedContextTests
    {
        [Test]
        public void CogniStreamerAuthenticatedContext_PassArgumentsToConstructor_ShouldSetProperties()
        {
            var owinContext = new Mock<IOwinContext>().Object;
            var accessToken = Guid.NewGuid().ToString("N");
            var user = JObject.Parse("{ a: 12345 }");
            var options = new CogniStreamerAuthenticationOptions();
            var context = new CogniStreamerAuthenticatedContext(owinContext, options, user, accessToken, "1400");
            Assert.That(context.OwinContext, Is.EqualTo(owinContext));
            Assert.That(context.Options, Is.EqualTo(options));
            Assert.That(context.User["a"].Value<int>(), Is.EqualTo(12345));
            Assert.That(context.AccessToken, Is.EqualTo(accessToken));
            Assert.That(context.ExpiresIn, Is.EqualTo(TimeSpan.FromSeconds(1400)));
        }

        [Test]
        public void CogniStreamerAuthenticatedContext_PassUserObjectToConstructor_ShouldSetProperties()
        {
            var owinContext = new Mock<IOwinContext>().Object;
            var user = JObject.Parse(@"{
                id: 'dcec99ad-28e1-4194-a4e0-f22148963cc5',
                username: 'cashj',
                firstName: 'Johnny',
                lastName: 'Cash',
                email: 'cashj@walktheline.com'
            }");
            var options = new CogniStreamerAuthenticationOptions();
            var context = new CogniStreamerAuthenticatedContext(owinContext, options, user, string.Empty, "3600");
            Assert.That(context.Id, Is.EqualTo(new Guid("dcec99ad-28e1-4194-a4e0-f22148963cc5")));
            Assert.That(context.Username, Is.EqualTo("cashj"));
            Assert.That(context.FirstName, Is.EqualTo("Johnny"));
            Assert.That(context.LastName, Is.EqualTo("Cash"));
            Assert.That(context.Email, Is.EqualTo("cashj@walktheline.com"));
        }
    }
}
