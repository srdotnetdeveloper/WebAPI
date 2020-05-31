using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace External_BearerTokenImplementation
{
    public class MyOthorizationServiceProvider_New : OAuthAuthorizationServerProvider
    {
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }


        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originClient = context.Ticket.Properties.Dictionary["client_id"];
            var currenClient = context.ClientId;
            if (originClient != currenClient)
            {
                context.SetError("Error");
                return Task.FromResult<object>(null);
            }
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim(ClaimTypes.Name, context.ClientId));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
        #region[CreateProperties]

        // will get these properties while post /token
        public static AuthenticationProperties CreateProperties(OAuthValidateClientAuthenticationContext context)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {

                { "client_id", context.ClientId}
            };
            return new AuthenticationProperties(data);
        }
        #endregion
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.OwinContext.Set<string>("as:clientAllowedOrigin", "*");

            await Task.Run(() => context.Validated());
        }
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            using (var db = new MyDbContext())
            {
                if (db != null)
                {
                    var user = db.UserMasters.ToList().Where(o => o.UserName == context.UserName && o.UserPassword == context.Password).FirstOrDefault();
                    if (user == null)
                    {
                        context.SetError("invalid_grant", "The user name or password is incorrect.");
                        return;
                    }
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, context.UserName));
            identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "as:client_id", context.ClientId
                    },
                    {
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);

        }

        

    }
}