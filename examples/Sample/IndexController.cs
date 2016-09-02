using System.Security.Claims;
using System.Web.Http;

namespace Sample
{
    [Authorize]
    [RoutePrefix("")]
    public class IndexController : ApiController
    {
        [Route("")]
        public string Get()
        {
            var identity = this.User.Identity as ClaimsIdentity;
            return $"Authenticated as {identity.FindFirst(ClaimTypes.GivenName).Value} {identity.FindFirst(ClaimTypes.Surname).Value}!";
        }
    }
}