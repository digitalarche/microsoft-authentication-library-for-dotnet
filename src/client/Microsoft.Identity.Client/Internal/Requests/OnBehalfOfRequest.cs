// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client.ApiConfig.Parameters;
using Microsoft.Identity.Client.Cache.Items;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.TelemetryCore.Internal.Events;
using System.Linq;

namespace Microsoft.Identity.Client.Internal.Requests
{
    internal class OnBehalfOfRequest : RequestBase
    {
        private readonly AcquireTokenOnBehalfOfParameters _onBehalfOfParameters;

        public OnBehalfOfRequest(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            AcquireTokenOnBehalfOfParameters onBehalfOfParameters)
            : base(serviceBundle, authenticationRequestParameters, onBehalfOfParameters)
        {
            _onBehalfOfParameters = onBehalfOfParameters;
        }

        protected override async Task<AuthenticationResult> ExecuteAsync(CancellationToken cancellationToken)
        {
            if (AuthenticationRequestParameters.Scope == null || !AuthenticationRequestParameters.Scope.Any())
            {
                throw new MsalClientException(
                    MsalError.ScopesRequired,
                    MsalErrorMessage.ScopesRequired);
            }

            await ResolveAuthorityEndpointsAsync().ConfigureAwait(false);

            var msalTokenResponse = await SendTokenRequestAsync(GetBodyParameters(), cancellationToken).ConfigureAwait(false);
            return await CacheTokenResponseAndCreateAuthenticationResultAsync(msalTokenResponse).ConfigureAwait(false);
        }

        protected override void EnrichTelemetryApiEvent(ApiEvent apiEvent)
        {
            apiEvent.IsConfidentialClient = true;
        }

        private Dictionary<string, string> GetBodyParameters()
        {
            var dict = new Dictionary<string, string>
            {
                [OAuth2Parameter.GrantType] = _onBehalfOfParameters.UserAssertion.AssertionType,
                [OAuth2Parameter.Assertion] = _onBehalfOfParameters.UserAssertion.Assertion,
                [OAuth2Parameter.RequestedTokenUse] = OAuth2RequestedTokenUse.OnBehalfOf
            };
            return dict;
        }
    }
}
