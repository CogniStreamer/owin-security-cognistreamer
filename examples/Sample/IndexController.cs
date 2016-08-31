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
            return "Authenticated!";
        }
    }
}