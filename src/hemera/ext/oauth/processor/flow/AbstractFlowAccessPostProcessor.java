package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.AccessTokenPair;
import hemera.ext.oauth.request.flow.FlowAccessPostRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;

/**
 * <code>AbstractFlowAccessPostProcessor</code> defines
 * the processor abstraction for the OAuth resource
 * access token action post operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAccessPostProcessor<C extends AbstractConsumer> extends
		AbstractFlowAccessProcessor<FlowAccessPostRequest, C> {

	@Override
	protected final FlowAccessResponse processRequest(final FlowAccessPostRequest request, final C consumer) throws Exception {
		// Generate new access token and refresh token.
		final AccessTokenPair tokenPair = consumer.newAccessToken(request.consumerSecret, request.authorizationToken);
		// Invalid secret or authorization token.
		if (tokenPair == null) return new FlowAccessResponse(EHttpStatus.C400_BadRequest, "Invalid consumer secret or invalid authorization token.");
		// Success.
		else return new FlowAccessResponse(tokenPair.accessToken, tokenPair.refreshToken, tokenPair.accessExpiration);
	}

	@Override
	public Class<FlowAccessPostRequest> getRequestType() {
		return FlowAccessPostRequest.class;
	}
}
