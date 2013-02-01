package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAccessPostRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;
import hemera.ext.oauth.token.AbstractAuthorizationToken;
import hemera.ext.oauth.token.AccessTokenPair;

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
		// Retrieve authorization token.
		final AbstractAuthorizationToken authorizationToken = this.getAuthorizationToken(request.authorizationToken);
		if (authorizationToken == null) throw new IllegalArgumentException("Invalid authorization token.");
		// Generate new access token and refresh token.
		final AccessTokenPair tokenPair = consumer.newAccessToken(request.consumerSecret, authorizationToken);
		// Invalid secret or authorization token.
		if (tokenPair == null) return new FlowAccessResponse(EHttpStatus.C400_BadRequest, "Invalid consumer secret or invalid authorization token.");
		// Success.
		else return new FlowAccessResponse(tokenPair);
	}

	/**
	 * Retrieve the authorization token with given token
	 * value.
	 * @param value The <code>String</code> token value.
	 * @return The <code>AbstractAuthorizationToken</code>.
	 * <code>null</code> if there isn't a match.
	 * @throws Exception If any processing failed.
	 */
	protected abstract AbstractAuthorizationToken getAuthorizationToken(final String value) throws Exception;

	@Override
	public Class<FlowAccessPostRequest> getRequestType() {
		return FlowAccessPostRequest.class;
	}
}
