using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Moq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using Owin.Security.CogniStreamer.Provider;

namespace Owin.Security.CogniStreamer.Tests.Provider
{
    [TestFixture]
    public class CogniStreamerAuthenticationProviderTests
    {
        private Mock<IOwinContext> owinContextMock;
        private JObject user;
        private AuthenticationTicket ticket;
        private CogniStreamerAuthenticationProvider providerUnderTest;

        [SetUp]
        public void SetUp()
        {
            this.user = new JObject();
            this.ticket = new AuthenticationTicket(new ClaimsIdentity(), new AuthenticationProperties());
            this.owinContextMock = new Mock<IOwinContext>();
            this.providerUnderTest = new CogniStreamerAuthenticationProvider();
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_DefaultOnAuthenticatedImplementation_ShouldNotThrowException()
        {
            var options = new CogniStreamerAuthenticationOptions();
            var context = new CogniStreamerAuthenticatedContext(this.owinContextMock.Object, options, this.user, string.Empty, string.Empty);
            Assert.That(() => this.providerUnderTest.Authenticated(context), Throws.Nothing);
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_DefaultOnReturnEndpointImplementation_ShouldNotThrowException()
        {
            var context = new CogniStreamerReturnEndpointContext(this.owinContextMock.Object, this.ticket);
            Assert.That(() => this.providerUnderTest.ReturnEndpoint(context), Throws.Nothing);
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_DefaultOnApplyRedirectImplementation_ShouldRedirectResponse()
        {
            var options = new CogniStreamerAuthenticationOptions();
            var properties = new AuthenticationProperties();
            var context = new CogniStreamerApplyRedirectContext(this.owinContextMock.Object, options, properties, "https://www.test.org");

            var responseMock = new Mock<IOwinResponse>();
            this.owinContextMock.SetupGet(x => x.Response).Returns(responseMock.Object);

            Assert.That(() => this.providerUnderTest.ApplyRedirect(context), Throws.Nothing);
            responseMock.Verify(x => x.Redirect("https://www.test.org"), Times.Once);
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_CallAuthenticated_ShouldInvokeOnAuthenticated()
        {
            var callbacksMock = new Mock<IProviderCallbacks>();
            var options = new CogniStreamerAuthenticationOptions();
            var context = new CogniStreamerAuthenticatedContext(this.owinContextMock.Object, options, this.user, string.Empty, string.Empty);
            this.providerUnderTest.OnAuthenticated = callbacksMock.Object.OnAuthenticated;
            this.providerUnderTest.Authenticated(context);
            callbacksMock.Verify(x => x.OnAuthenticated(context), Times.Once);
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_CallReturnEndpoint_ShouldInvokeOnReturnEndpoint()
        {
            var callbacksMock = new Mock<IProviderCallbacks>();
            var context = new CogniStreamerReturnEndpointContext(this.owinContextMock.Object, this.ticket);
            this.providerUnderTest.OnReturnEndpoint = callbacksMock.Object.OnReturnEndpoint;
            this.providerUnderTest.ReturnEndpoint(context);
            callbacksMock.Verify(x => x.OnReturnEndpoint(context), Times.Once);
        }

        [Test]
        public void CogniStreamerAuthenticationProvider_CallApplyRedirect_ShouldInvokeOnApplyRedirect()
        {
            var callbacksMock = new Mock<IProviderCallbacks>();
            var options = new CogniStreamerAuthenticationOptions();
            var properties = new AuthenticationProperties();
            var context = new CogniStreamerApplyRedirectContext(this.owinContextMock.Object, options, properties, "https://www.test.org");

            this.providerUnderTest.OnApplyRedirect = callbacksMock.Object.OnApplyRedirect;
            this.providerUnderTest.ApplyRedirect(context);
            callbacksMock.Verify(x => x.OnApplyRedirect(context), Times.Once);
        }

        public interface IProviderCallbacks
        {
            Task OnAuthenticated(CogniStreamerAuthenticatedContext context);
            Task OnReturnEndpoint(CogniStreamerReturnEndpointContext context);
            void OnApplyRedirect(CogniStreamerApplyRedirectContext context);
        }
    }
}
