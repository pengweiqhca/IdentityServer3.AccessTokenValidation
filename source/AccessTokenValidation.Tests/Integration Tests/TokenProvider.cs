﻿using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityModel.Client;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class TokenProvider
    {
        private readonly IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            IssuerName = TokenFactory.DefaultIssuer,
            SigningCertificate = new X509Certificate2(Convert.FromBase64String(TokenFactory.DefaultPublicKey)),

            ValidationMode = ValidationMode.Local
        };

        [Fact]
        public async Task Token_From_QueryString()
        {
            var provider = new OAuthBearerAuthenticationProvider
            {
                OnRequestToken = c =>
                {
                    var qs = c.OwinContext.Request.Query;
                    c.Token = qs.Get("access_token");

                    return Task.FromResult(0);
                }
            };

            _options.TokenProvider = provider;

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            var result = await client.GetAsync("http://test?access_token=" + token);
            result.StatusCode.Should().Be(HttpStatusCode.OK);

        }

        [Fact]
        public async Task Valid_Token_With_ValidatingIdentity_Deny_Access()
        {
            var provider = new OAuthBearerAuthenticationProvider
            {
                OnValidateIdentity = c =>
                {
                    c.Rejected();

                    return Task.FromResult(0);
                }
            };

            _options.TokenProvider = provider;

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());
            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}
