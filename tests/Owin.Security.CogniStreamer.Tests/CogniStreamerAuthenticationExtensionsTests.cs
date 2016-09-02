using System;
using Microsoft.Owin.Builder;
using Moq;
using NUnit.Framework;

namespace Owin.Security.CogniStreamer.Tests
{
    [TestFixture]
    public class CogniStreamerAuthenticationExtensionsTests
    {
        [Test]
        public void UseCogniStreamerAuthentication_NullAsIAppBuilder_ShouldThrowException()
        {
            IAppBuilder app = null;
            var options = new CogniStreamerAuthenticationOptions();
            Assert.That(() => app.UseCogniStreamerAuthentication(options), Throws.ArgumentNullException);
        }

        [Test]
        public void UseCogniStreamerAuthentication_NullAsOptions_ShouldThrowException()
        {
            var app = new AppBuilder();
            CogniStreamerAuthenticationOptions options = null;
            Assert.That(() => app.UseCogniStreamerAuthentication(options), Throws.ArgumentNullException);
        }

        [Test]
        public void UseCogniStreamerAuthentication_PassingIAppBuilder_ReturnsSameInstanceOfIAppBuilder()
        {
            var app = new AppBuilder();
            var options = new CogniStreamerAuthenticationOptions();
            Assert.That(app, Is.EqualTo(app));
        }

        [Test]
        public void UseCogniStreamerAuthentication_PassingIAppBuilderAndOptions_ShouldRegisterMiddleware()
        {
            var appMock = new Mock<IAppBuilder>();
            var app = appMock.Object;
            var options = new CogniStreamerAuthenticationOptions();
            app.UseCogniStreamerAuthentication(options);
            appMock.Verify(x => x.Use(typeof(CogniStreamerAuthenticationMiddleware), app, options), Times.Once);
        }

        [Test]
        public void UseCogniStreamerAuthentication_PassingIAppBuilderAndSeparateOptions_ShouldRegisterMiddlewareWithCorrectOptions()
        {
            CogniStreamerAuthenticationOptions options = null;
            var baseUrl = new Uri("https://mybaseurl.com");
            var clientId = Guid.NewGuid().ToString("N");
            var clientSecret = Guid.NewGuid().ToString("N");
            var appMock = new Mock<IAppBuilder>();
            appMock
                .Setup(x => x.Use(typeof(CogniStreamerAuthenticationMiddleware), It.IsAny<IAppBuilder>(), It.IsAny<CogniStreamerAuthenticationOptions>()))
                .Callback<Object, Object[]>((type, args) => options = (CogniStreamerAuthenticationOptions)args[1]);
            var app = appMock.Object;
            app.UseCogniStreamerAuthentication(baseUrl, clientId, clientSecret);
            Assert.That(options, Is.Not.Null);
            Assert.That(options.PortalBaseUrl, Is.EqualTo(baseUrl));
            Assert.That(options.ClientId, Is.EqualTo(clientId));
            Assert.That(options.ClientSecret, Is.EqualTo(clientSecret));
        }
    }
}
