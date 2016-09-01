using System;
using Microsoft.Owin.Security;
using NUnit.Framework;

namespace Owin.Security.CogniStreamer.Tests
{
    [TestFixture]
    public class CogniStreamerAuthenticationOptionsTests
    {
        [Test]
        public void Constructor_NewInstance_ShouldSetProperties()
        {
            var options = new CogniStreamerAuthenticationOptions();
            Assert.That(options.BackchannelTimeout, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.Caption, Is.EqualTo("CogniStreamer"));
            Assert.That(options.AuthenticationMode, Is.EqualTo(AuthenticationMode.Passive));
            Assert.That(options.Scope, Contains.Item("login"));
            Assert.That(options.Scope, Contains.Item("profile"));
        }
    }
}
