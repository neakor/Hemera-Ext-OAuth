package hemera.ext.oauth.processor.flow;

import hemera.core.structure.AbstractProcessor;
import hemera.core.structure.AbstractResponse;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.AbstractFlowRequest;

/**
 * <code>AbstractFlowProcessor</code> defines the base
 * abstraction of an OAuth resource processor for
 * all OAuth flow actions.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.1
 */
public abstract class AbstractFlowProcessor<RQ extends AbstractFlowRequest, RS extends AbstractResponse, C extends AbstractConsumer>
extends AbstractProcessor<RQ, RS> {

	@Override
	protected RS processRequest(final RQ request) throws Exception {
		// Retrieve consumer.
		final C consumer = this.getConsumer(request);
		if (consumer == null) {
			return this.noSuchConsumerResponse(request);
		}
		// Verify redirect URL.
		final boolean redirectValid = consumer.verifyRedirectURL(request.redirectURL);
		if (!redirectValid) {
			return this.invalidRedirectURLResponse(request);
		}
		// Perform specific operation.
		return this.processRequest(request, consumer);
	}
	
	/**
	 * Retrieve the consumer making the request.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>C</code> consumer instance.
	 * <code>null</code> if there is no such consumer.
	 * @throws Exception If any processing failed.
	 */
	protected abstract C getConsumer(final RQ request) throws Exception;
	
	/**
	 * Perform the operation specific logic to process
	 * the request for the given consumer.
	 * @param request The <code>RQ</code> request.
	 * @param consumer The <code>C</code> consumer.
	 * @return The <code>RS</code> response.
	 * @throws Exception If any processing failed.
	 */
	protected abstract RS processRequest(final RQ request, final C consumer) throws Exception;
	
	/**
	 * Create a new error response in the case that
	 * the request specified consumer does not exist.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>RS</code> response.
	 */
	protected abstract RS noSuchConsumerResponse(final RQ request);
	
	/**
	 * Create a new error response in the case that
	 * the request specified redirect URL does not
	 * match with the registered consumer.
	 * @param request The <code>RQ</code> request.
	 * @return The <code>RS</code> response.
	 */
	protected abstract RS invalidRedirectURLResponse(final RQ request);
}
