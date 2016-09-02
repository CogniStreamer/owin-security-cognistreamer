using Microsoft.Owin;
using Microsoft.Owin.Security;
using Moq;
using NUnit.Framework;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer.Tests.Provider
{
    [TestFixture]
    public class CogniStreamerApplyRedirectContextTests
    {
        [Test]
        public void CogniStreamerApplyRedirectContext_PassArguments_ShouldAssignProperties()
        {
            var owinContext = new Mock<IOwinContext>().Object;
            var options = new CogniStreamerAuthenticationOptions();
            var properties = new AuthenticationProperties();
            var context = new CogniStreamerApplyRedirectContext(owinContext, options, properties, "https://someredirecturi.com/test");
            Assert.That(context.OwinContext, Is.EqualTo(owinContext));
            Assert.That(context.Options, Is.EqualTo(options));
            Assert.That(context.Properties, Is.EqualTo(properties));
            Assert.That(context.RedirectUri, Is.EqualTo("https://someredirecturi.com/test"));
        }
    }
}
