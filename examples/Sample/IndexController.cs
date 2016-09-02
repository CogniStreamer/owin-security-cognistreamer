using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Microsoft.Owin.Security.Cookies;
using Owin.Security.CogniStreamer;

namespace Sample
{
    [Authorize]
    [RoutePrefix("")]
    public class IndexController : ApiController
    {
        [HttpGet]
        [Route("")]
        public string Get()
        {
            var identity = this.User.Identity as ClaimsIdentity;
            return $"Authenticated as {identity.FindFirst(ClaimTypes.GivenName).Value} {identity.FindFirst(ClaimTypes.Surname).Value}!";
        }

        [HttpGet]
        [Route("signout")]
        public void SignOut()
        {
            this.Request.GetOwinContext().Authentication.SignOut(
                CookieAuthenticationDefaults.AuthenticationType,
                CogniStreamerAuthenticationDefaults.AuthenticationType);
        }
    }
}