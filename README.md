# Login-with-Facebook
Allows to login with FB using Auth, Identity and Facebook Client


FB Authentication 
----------------------------------
DLLs which will be required 
----------------------------------
Microsoft.AspNet.Identity
Microsoft.Owin.Security
Microsoft.Owin.Security.Facebook
Facebook - version 6.0.10.0

----------------------------------
In Startup file - Configuration Method
----------------------------------
// Following code is used for FB authentication. Its using FacebookAuthenticationProvider() & //FacebookClient() for getting public profile data of user
            app.UseFacebookAuthentication(new FacebookAuthenticationOptions
            {
                AppId = "AppId",
                AppSecret = "AppSecret",
                Scope = {
                           "email" 
                        },
                Provider = new FacebookAuthenticationProvider
                {
                    OnAuthenticated = context =>
                    {
                        context.Identity.AddClaim(new Claim("FacebookAccessToken", context.AccessToken));
                        return Task.FromResult(true);
                    }
                }
            });

            app.UseGoogleAuthentication(clientId: "clientID", clientSecret: "clientSecret");

---------------------------------------------------------------------------------------------
In Login Controller 
---------------------------------------------------------------------------------------------
[HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Login", new { ReturnUrl = returnUrl }));
        }


[AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
 // get login info from external login providers i.e facebook & google
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Index", "Login", new { isExternalLoginFailed = true });
            }

if (loginInfo.Login.LoginProvider == "Facebook")
            {
                var identity = AuthenticationManager.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);
                var accessToken = identity.FindFirstValue("FacebookAccessToken");
                var fb = new FacebookClient(accessToken);
                dynamic myInfo = fb.Get(Constants.FacebookRequiredPermissions); // specify the fields       
            }
In Login Controller add following

 // Used for XSRF protection when adding external logins
        /// <summary>
        /// The xsrf key.
        /// </summary>
        private const string XsrfKey = "XsrfId";

        /// <summary>
        /// Microsoft OWIN Authentication Manager
        /// </summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        /// <summary>
        /// Used to redirect user to specified URL in application after successful third party authentication 
        /// </summary>
        private class ChallengeResult : HttpUnauthorizedResult
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="ChallengeResult"/> class.
            /// </summary>
            /// <param name="provider">
            /// The provider.
            /// </param>
            /// <param name="redirectUri">
            /// The redirect uri.
            /// </param>
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="ChallengeResult"/> class.
            /// </summary>
            /// <param name="provider">
            /// The provider.
            /// </param>
            /// <param name="redirectUri">
            /// The redirect uri.
            /// </param>
            /// <param name="userId">
            /// The user id.
            /// </param>
            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            /// <summary>
            /// Gets or sets the login provider.
            /// </summary>
            public string LoginProvider { get; set; }

            /// <summary>
            /// Gets or sets the redirect uri.
            /// </summary>
            public string RedirectUri { get; set; }

            /// <summary>
            /// Gets or sets the user id.
            /// </summary>
            public string UserId { get; set; }

            /// <summary>
            /// The execute result.
            /// </summary>
            /// <param name="context">
            /// The context.
            /// </param>
            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }

                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        
        public const string FacebookRequiredPermissions = "/me?fields=email,first_name,last_name,gender";
