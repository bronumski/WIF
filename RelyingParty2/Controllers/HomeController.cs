using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RelyingParty.Controllers
{
    
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignOut()
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            FederatedAuthentication.WSFederationAuthenticationModule.SignOut(false);

            var redirect = WSFederationAuthenticationModule.GetFederationPassiveSignOutUrl(
                "http://localhost:52292/Authentication/Token", "http://localhost:56763/Home", string.Empty);

            return Redirect(redirect);
        }

    }
}
