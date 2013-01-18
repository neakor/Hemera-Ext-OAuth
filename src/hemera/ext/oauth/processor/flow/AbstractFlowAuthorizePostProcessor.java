package hemera.ext.oauth.processor.flow;

import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAuthorizePostRequest;
import hemera.ext.oauth.response.flow.FlowAuthorizeResponse;

/**
 * <code>AbstractFlowAuthorizePostProcessor</code>
 * defines the abstraction of an OAuth resource processor
 * for authorize action post operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAuthorizePostProcessor<C extends AbstractConsumer>
extends AbstractFlowAuthorizeProcessor<FlowAuthorizePostRequest, C> {

	@Override
	protected final FlowAuthorizeResponse processRequest(final FlowAuthorizePostRequest request, final C consumer) throws Exception {
		final String token = consumer.newAuthorizationToken(request.permissions, request.userid);
		return new FlowAuthorizeResponse(token);
	}
	
	@Override
	public Class<FlowAuthorizePostRequest> getRequestType() {
		return FlowAuthorizePostRequest.class;
	}
}
