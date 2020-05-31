
//RefreshTokenProvider:

//This class is inherited from IAuthenticationTokenProvider interface and provides implementation for creating the refresh token and regenerate the new access token, if it is expired.

//CreateAsync(): This method is responsible for creating the new access token.
//ReceiveAsync(): This method is responsible for regenerate the new access token by using existing  refresh token, if it is expired.
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;

namespace External_BearerTokenImplementation
{
    public class RefreshTokenProvider : AuthenticationTokenProvider
    {
        private const string IsRefreshTokenExpiredName = "IsRefreshTokenExpired";

        #region ctor
        public RefreshTokenProvider()
        {
        }
        #endregion

        public async override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            if (!context.OwinContext.Environment.ContainsKey(IsRefreshTokenExpiredName) || (bool)context.OwinContext.Environment[IsRefreshTokenExpiredName])
            {
                var hrs = int.Parse(ConfigurationManager.AppSettings["RefreshTokenExpirationHours"]);
                var now = DateTime.UtcNow;
                context.Ticket.Properties.IssuedUtc = now;
                context.Ticket.Properties.ExpiresUtc = now.AddMinutes(3); //now.AddHours(hrs);
                context.SetToken(context.SerializeTicket());
            }
        }
        //public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        //{

        //    var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
        //    context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

        //    string hashedTokenId = Helper.GetHash(context.Token);

        //    using (AuthRepository _repo = new AuthRepository())
        //    {
        //        var refreshToken = await _repo.FindRefreshToken(hashedTokenId);

        //        if (refreshToken != null)
        //        {
        //            //Get protectedTicket from refreshToken class
        //            context.DeserializeTicket(refreshToken.ProtectedTicket);
        //            var result = await _repo.RemoveRefreshToken(hashedTokenId);
        //        }
        //    }
        //}
       
        public async override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { ConfigurationManager.AppSettings["CorsOrigins"] });
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Method", new[] { "POST" });

            AuthenticationTicket ticket = null;
            var identity = new ClaimsIdentity();
            var props = new AuthenticationProperties();
            ticket = new AuthenticationTicket(identity, props);
            context.SetTicket(ticket);
            context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow;
            context.Ticket.Properties.IssuedUtc = DateTime.UtcNow;

            ////var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            ////context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });
            //context.DeserializeTicket(context.Token);
            //if (context.Ticket.Properties.ExpiresUtc > DateTime.Now)
            //context.OwinContext.Environment[IsRefreshTokenExpiredName] = false;

        }
    }
}