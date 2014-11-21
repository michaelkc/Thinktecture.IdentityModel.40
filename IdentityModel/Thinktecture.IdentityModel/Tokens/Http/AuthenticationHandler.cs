/*
 * Copyright (c) Dominick Baier & Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Thinktecture.IdentityModel.Claims;
using Microsoft.IdentityModel.Claims;
using System;
using System.IdentityModel.Tokens;
using System.Web;
using System.Text;

namespace Thinktecture.IdentityModel.Tokens.Http
{
    public class AuthenticationHandler : DelegatingHandler
    {
        HttpAuthentication _authN;

        public AuthenticationHandler(AuthenticationConfiguration configuration)
        {
            _authN = new HttpAuthentication(configuration);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!OwinAuthenticationPerformed())
            {
                if (_authN.Configuration.InheritHostClientIdentity == false)
                {
                    SetPrincipal(Principal.Anonymous, request);
                }


                try
                {
                    // try to authenticate
                    // returns an anonymous principal if no credential was found
                    var principal = _authN.Authenticate(request);

                    if (principal == null)
                    {
                        throw new InvalidOperationException("No principal set");
                    }

                    if (principal.Identity.IsAuthenticated)
                    {
                        // check for token request - if yes send token back and return
                        if (_authN.IsSessionTokenRequest(request))
                        {
                            return SendSessionTokenResponse(principal);
                        }

                        // else set the principal
                        //HttpRequestMessageExtensions.GetRequestContext(request);
                        
                        SetPrincipal(principal, request);
                    }
                }
                catch (SecurityTokenValidationException)
                {
                    return SendUnauthorizedResponse();
                }
            }

            return base.SendAsync(request, cancellationToken).ContinueWith(
                (task) =>
                {
                    var response = task.Result;

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        SetAuthenticateHeader(response);
                    }

                    return response;
                });
        }

        private static bool OwinAuthenticationPerformed()
        {
            IIdentity currentIdentity = Thread.CurrentPrincipal.Identity;
            return currentIdentity.IsAuthenticated && string.Equals(currentIdentity.AuthenticationType, "Federation", StringComparison.InvariantCultureIgnoreCase);
        }

        private Task<HttpResponseMessage> SendUnauthorizedResponse()
        {
            return Task<HttpResponseMessage>.Factory.StartNew(() =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                SetAuthenticateHeader(response);

                return response;
            });
        }

        private Task<HttpResponseMessage> SendSessionTokenResponse(ClaimsPrincipal principal)
        {
            var token = _authN.CreateSessionToken(principal);
            var tokenResponse = _authN.CreateSessionTokenResponse(token);

            return Task<HttpResponseMessage>.Factory.StartNew(() =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(tokenResponse, Encoding.UTF8, "application/json");

                return response;
            });
        }

        protected virtual void SetAuthenticateHeader(HttpResponseMessage response)
        {
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(_authN.Configuration.DefaultAuthenticationScheme));
        }

        protected virtual void SetPrincipal(ClaimsPrincipal principal, HttpRequestMessage request)
        {
            Thread.CurrentPrincipal = principal;

            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }
        }
    }
}