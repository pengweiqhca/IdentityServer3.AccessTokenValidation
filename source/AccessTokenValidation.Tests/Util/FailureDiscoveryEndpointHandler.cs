using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class FailureDiscoveryEndpointHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadGateway)
            {
                RequestMessage = request,
                Content = new StringContent("Bad Gateway")
            };
            return Task.FromResult(response);
        }
    }
}
