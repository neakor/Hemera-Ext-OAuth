package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.core.structure.enumn.ERedirect;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAuthorizePostRequest;
import hemera.ext.oauth.response.flow.FlowAuthorizeResponse;

/**
 * <code>AbstractFlowAuthorizeProcessor</code> defines
 * the processor abstraction for the OAuth resource
 * authorize action.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
abstract class AbstractFlowAuthorizeProcessor<RQ extends FlowAuthorizePostRequest, C extends AbstractConsumer> extends
		AbstractFlowProcessor<RQ, FlowAuthorizeResponse, C> {
	
	@Override
	protected final FlowAuthorizeResponse noSuchConsumerResponse(final RQ request) {
		return new FlowAuthorizeResponse(EHttpStatus.C404_NotFound, "There is no such consumer.");
	}

	@Override
	protected final FlowAuthorizeResponse invalidRedirectURLResponse(final RQ request) {
		return new FlowAuthorizeResponse(EHttpStatus.C417_ExpectationFailed, "Invalid redirect URL.");
	}

	@Override
	protected final FlowAuthorizeResponse exceptionResponse(final RQ request, final Exception e) {
		return new FlowAuthorizeResponse(EHttpStatus.C500_InternalServerError, e.getMessage());
	}
	
	@Override
	public final String getRedirectURI(final RQ request) {
		return this.getAuthorizationServerRedirectURI(request);
	}
	
	/**
	 * Retrieve the redirect URI to the authorization
	 * server for the given request, which needs to
	 * authenticate user and authorize consumer.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>String</code> redirect URI.
	 */
	protected abstract String getAuthorizationServerRedirectURI(final RQ request);

	@Override
	public final ERedirect getRedirectBehavior(final RQ request) {
		// Check request data first.
		if (request.userid == null || request.authServerKey == null || request.authServerSecret == null) {
			return ERedirect.RedirectBeforeInvoke;
		}
		try {
			// Retrieve and verify authorization server consumer.
			final C consumer = this.getAuthorizationServerConsumer(request.authServerKey);
			if (consumer == null) throw new IllegalArgumentException("Invalid authorization server consumer data.");
			final boolean valid = consumer.verifySecret(request.authServerSecret);
			if (!valid) throw new IllegalArgumentException("Invalid authorization server consumer data.");
			// Check for consumer privilege.
			if (consumer.hasUserAuthorizationPrivilege()) return ERedirect.Invoke;
			else return ERedirect.RedirectBeforeInvoke;
		} catch (final Exception e) {
			this.logger.severe("Retrieving authorization server consumer failed.");
			this.logger.exception(e);
			return ERedirect.RedirectBeforeInvoke;
		}
	}
	
	/**
	 * Retrieve the authorization server consumer.
	 * @param key The <code>String</code> authorization
	 * server consumer key.
	 * @return The <code>Consumer</code> instance. Or
	 * <code>null</code> if retrieval failed.
	 * @throws Exception If retrieval failed.
	 */
	protected abstract C getAuthorizationServerConsumer(final String key) throws Exception;
}
