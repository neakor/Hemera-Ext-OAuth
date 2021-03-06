package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAccessPutRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;
import hemera.ext.oauth.token.AbstractRefreshToken;
import hemera.ext.oauth.token.AccessTokenPair;

/**
 * <code>AbstractFlowAccessPutProcessor</code> defines
 * the processor abstraction for the OAuth resource
 * access token action put operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.1
 */
public abstract class AbstractFlowAccessPutProcessor<RQ extends FlowAccessPutRequest, C extends AbstractConsumer> extends
AbstractFlowAccessProcessor<RQ, C> {

	@Override
	protected FlowAccessResponse processRequest(final RQ request, final C consumer) throws Exception {
		// Retrieve refresh token.
		final AbstractRefreshToken refreshToken = this.getRefreshToken(request.refreshToken);
		if (refreshToken == null) throw new IllegalArgumentException("Invalid refresh token.");
		// Generate new access token and refresh token.
		final AccessTokenPair tokenPair = consumer.refreshAccessToken(request.consumerSecret, refreshToken);
		// Invalid secret or refresh token.
		if (tokenPair == null) return new FlowAccessResponse(EHttpStatus.C400_BadRequest, "Invalid consumer secret or invalid refresh token.");
		// Success.
		else return new FlowAccessResponse(tokenPair);
	}

	/**
	 * Retrieve the refresh token with given token value.
	 * @param value The <code>String</code> token value.
	 * @return The <code>AbstractRefreshToken</code>. Or
	 * <code>null</code> if there isn't a match.
	 * @throws Exception If any processing failed.
	 */
	protected abstract AbstractRefreshToken getRefreshToken(final String value) throws Exception;
}
