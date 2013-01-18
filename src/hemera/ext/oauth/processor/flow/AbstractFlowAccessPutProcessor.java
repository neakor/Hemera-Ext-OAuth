package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.AccessTokenPair;
import hemera.ext.oauth.request.flow.FlowAccessPutRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;

/**
 * <code>AbstractFlowAccessPutProcessor</code> defines
 * the processor abstraction for the OAuth resource
 * access token action put operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAccessPutProcessor<C extends AbstractConsumer> extends
AbstractFlowAccessProcessor<FlowAccessPutRequest, C> {

	@Override
	protected final FlowAccessResponse processRequest(final FlowAccessPutRequest request, final C consumer) throws Exception {
		// Generate new access token and refresh token.
		final AccessTokenPair tokenPair = consumer.refreshAccessToken(request.consumerSecret, request.refreshToken);
		// Invalid secret or refresh token.
		if (tokenPair == null) return new FlowAccessResponse(EHttpStatus.C400_BadRequest, "Invalid consumer secret or invalid refresh token.");
		// Success.
		else return new FlowAccessResponse(tokenPair.accessToken, tokenPair.refreshToken, tokenPair.accessExpiration);
	}

	@Override
	public Class<FlowAccessPutRequest> getRequestType() {
		return FlowAccessPutRequest.class;
	}
}
