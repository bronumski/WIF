using System;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using System.Web.Security;

namespace STS.Controllers
{
    [Authorize]
    public class AuthenticationController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            return View(new LoginModel { ReturnUrl = returnUrl });
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.UserName == "Foo")
                {
                    FormsAuthentication.SetAuthCookie("Foo", false);
                    return Redirect(model.ReturnUrl);
                }
            }

            return View(model);
        }

        public ActionResult Token(TokenModel tokenModel)
        {
            if (tokenModel.Wa == "wsignin1.0")
            {
                var securityTokenService = new CustomSecurityTokenService(new CustomSecurityTokenServiceConfiguration
                {
                    TokenIssuerName = "PassiveSTS",
                    SigningCredentials = new X509SigningCredentials(new X509Certificate2(Certs.Cert, "foo"))
                });
                var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri( Request.Url );
                SignInResponseMessage responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest( requestMessage, new ClaimsPrincipal(User), securityTokenService );
                tokenModel.Response = responseMessage;
                return View(tokenModel);
            }

            if (tokenModel.Wa == "wsignout1.0")
            {
                FormsAuthentication.SignOut();
                var signoutMessage = (SignOutRequestMessage)WSFederationMessage.CreateFromUri(Request.Url);
                return Redirect(signoutMessage.Reply);
            }
            return null;
        }
    }

    public class CustomSecurityTokenService : SecurityTokenService
    {
        private readonly CustomSecurityTokenServiceConfiguration _customSecurityTokenServiceConfiguration;

        public CustomSecurityTokenService(
            CustomSecurityTokenServiceConfiguration customSecurityTokenServiceConfiguration) :
                base(customSecurityTokenServiceConfiguration)
        {
            _customSecurityTokenServiceConfiguration = customSecurityTokenServiceConfiguration;
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            var scope = new Scope(request.AppliesTo.Uri.OriginalString, _customSecurityTokenServiceConfiguration.SigningCredentials);

            scope.TokenEncryptionRequired = false;

            scope.ReplyToAddress = scope.AppliesToAddress;

            return scope;
        }
        
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            var outputClaimsIdentity = new ClaimsIdentity();

            outputClaimsIdentity.AddClaim(new Claim(System.IdentityModel.Claims.ClaimTypes.Name, principal.Identity.Name));
            
            return outputClaimsIdentity;
        }
    }

    public class CustomSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
    }


    public class TokenModel
    {
        public string Wa { get; set; }
        public SignInResponseMessage Response { get; set; }
    }


    public class LoginModel
    {
        public string ReturnUrl { get; set; }
        public string UserName { get; set; }
    }
}
