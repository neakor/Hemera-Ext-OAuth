package hemera.ext.oauth.processor.flow;

import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAuthorizePostRequest;
import hemera.ext.oauth.response.flow.FlowAuthorizeResponse;
import hemera.ext.oauth.token.AbstractAuthorizationToken;

/**
 * <code>AbstractFlowAuthorizePostProcessor</code>
 * defines the abstraction of an OAuth resource processor
 * for authorize action post operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.1
 */
public abstract class AbstractFlowAuthorizePostProcessor<RQ extends FlowAuthorizePostRequest, C extends AbstractConsumer>
extends AbstractFlowAuthorizeProcessor<RQ, C> {

	@Override
	protected FlowAuthorizeResponse processRequest(final RQ request, final C consumer) throws Exception {
		final AbstractAuthorizationToken token = consumer.newAuthorizationToken(request.permissions, request.userid);
		return new FlowAuthorizeResponse(token);
	}
}
