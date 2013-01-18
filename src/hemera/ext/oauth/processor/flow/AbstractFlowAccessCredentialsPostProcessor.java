package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.AccessTokenPair;
import hemera.ext.oauth.request.flow.FlowAccessCredentialsPostRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;

/**
 * <code>AbstractFlowAccessCredentialsPostProcessor</code>
 * defines the processor abstraction for the OAuth
 * resource access token client credentials action post
 * operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAccessCredentialsPostProcessor<C extends AbstractConsumer> extends
		AbstractFlowAccessProcessor<FlowAccessCredentialsPostRequest, C> {

	@Override
	protected final FlowAccessResponse processRequest(final FlowAccessCredentialsPostRequest request, final C consumer) throws Exception {
		// Authenticate user.
		final String userid = this.authenticateUser(request, consumer);
		if (userid == null) return new FlowAccessResponse(EHttpStatus.C401_Unauthorized, "User authentication failed.");
		// Generate new access token and refresh token.
		final String permission = this.getClientCredentialsFlowPermission(consumer);
		final AccessTokenPair tokenPair = consumer.newAccessToken(request.consumerSecret, userid, permission);
		// Invalid secret or authorization token.
		if (tokenPair == null) return new FlowAccessResponse(EHttpStatus.C400_BadRequest, "Invalid consumer secret or unprivileged consumer.");
		// Success.
		else return new FlowAccessResponse(tokenPair.accessToken, tokenPair.refreshToken, tokenPair.accessExpiration);
	}
	
	/**
	 * Authenticate the user credentials in the given
	 * request with given consumer.
	 * @param request The <code>FlowAccessCredentialsPostRequest</code>.
	 * @param consumer The <code>C</code> consumer.
	 * @return The <code>String</code> user ID if the
	 * authentication succeeded. <code>null</code>
	 * otherwise.
	 * @throws Exception If any processing failed.
	 */
	protected abstract String authenticateUser(final FlowAccessCredentialsPostRequest request, final C consumer) throws Exception;
	
	/**
	 * Retrieve the default permission granted to the
	 * consumer via the client credentials flow.
	 * @param consumer The <code>C</code> consumer.
	 * @return The <code>String</code> permission.
	 * @throws Exception If any processing failed.
	 */
	protected abstract String getClientCredentialsFlowPermission(final C consumer) throws Exception;

	@Override
	public Class<FlowAccessCredentialsPostRequest> getRequestType() {
		return FlowAccessCredentialsPostRequest.class;
	}
}