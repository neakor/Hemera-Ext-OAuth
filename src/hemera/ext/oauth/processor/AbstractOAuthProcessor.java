package hemera.ext.oauth.processor;

import hemera.core.structure.AbstractProcessor;
import hemera.core.structure.interfaces.IResponse;
import hemera.ext.oauth.request.AbstractOAuthRequest;
import hemera.ext.oauth.token.AbstractAccessToken;

/**
 * <code>AbstractOAuthProcessor</code> defines the base
 * abstraction for processors of resources, which are
 * protected by OAuth access.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractOAuthProcessor<RQ extends AbstractOAuthRequest, RS extends IResponse> extends AbstractProcessor<RQ, RS> {

	@Override
	protected final RS processRequest(final RQ request) throws Exception {
		// Verify request.
		final AbstractAccessToken accessToken = this.verifyRequest(request);
		if (accessToken == null) return this.unauthorizedResponse(request);
		// Process request.
		return this.processAuthorizedRequest(accessToken, request);
	}
	
	/**
	 * Verify the given request to ensure that the OAuth
	 * access token is valid and has sufficient privilege
	 * to access the resource and perform the processor
	 * operation.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>AbstractAccessToken</code> if
	 * the request is valid. <code>null</code> otherwise.
	 * @throws Exception If verification failed.
	 */
	protected abstract AbstractAccessToken verifyRequest(final RQ request) throws Exception;
	
	/**
	 * Create an unauthorized response for the given
	 * request, which is unauthorized for the processor
	 * operation.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>RS</code> error response.
	 * @throws Exception If any processing failed.
	 */
	protected abstract RS unauthorizedResponse(final RQ request) throws Exception;
	
	/**
	 * Process the given authorized request and produce
	 * a response.
	 * @param accessToken The valid associated
	 * <code>AbstractAccessToken</code>.
	 * @param request The <code>RQ</code> authorized
	 * and verified request.
	 * @return The <code>RS</code> response.
	 * @throws Exception If any processing failed.
	 */
	protected abstract RS processAuthorizedRequest(final AbstractAccessToken accessToken, final RQ request) throws Exception;
}
