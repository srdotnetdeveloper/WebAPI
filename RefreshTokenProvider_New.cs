using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace External_BearerTokenImplementation
{
    public class RefreshTokenProvider_New : AuthenticationTokenProvider
    {
        private const string IsRefreshTokenExpiredName = "IsRefreshTokenExpired";
        private static ConcurrentDictionary<string, AuthenticationTicket> _refreshTokens = new ConcurrentDictionary<string, AuthenticationTicket>();



        #region ctor
        public RefreshTokenProvider_New()
        {
        }
        #endregion

        public async override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var guid = Guid.NewGuid().ToString();

            // copy all properties and set the desired lifetime of refresh token  
            var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
            {
                IssuedUtc = context.Ticket.Properties.IssuedUtc
               // ,ExpiresUtc = DateTime.UtcNow.AddMinutes(3)
            };

            var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

            _refreshTokens.TryAdd(guid, refreshTokenTicket);

            // consider storing only the hash of the handle  
            context.SetToken(guid);
        }
        
        public async override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Method", new[] { "POST" });
            context.DeserializeTicket(context.Token);
            AuthenticationTicket ticket;
            string header = context.OwinContext.Request.Headers["Authorization"];

            if (_refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
                context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow;
                context.Ticket.Properties.IssuedUtc = DateTime.UtcNow;
            }
        }
    }
}