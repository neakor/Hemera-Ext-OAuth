package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.FlowAuthorizeGetRequest;
import hemera.ext.oauth.response.flow.FlowAuthorizeResponse;
import hemera.ext.oauth.token.AbstractAuthorizationToken;

/**
 * <code>AbstractFlowAuthorizeGetProcessor</code> defines
 * the abstraction of an OAuth resource processor for
 * authorize action get operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAuthorizeGetProcessor<C extends AbstractConsumer>
extends AbstractFlowAuthorizeProcessor<FlowAuthorizeGetRequest, C> {

	@Override
	protected final FlowAuthorizeResponse processRequest(final FlowAuthorizeGetRequest request, final C consumer) throws Exception {
		// Retrieve existing token.
		final AbstractAuthorizationToken token = consumer.getValidAuthorizationToken(request.permissions, request.userid);
		if (token == null) {
			return new FlowAuthorizeResponse(EHttpStatus.C401_Unauthorized, "No valid authorization tokens.");
		} else {
			return new FlowAuthorizeResponse(token);
		}
	}

	@Override
	public Class<FlowAuthorizeGetRequest> getRequestType() {
		return FlowAuthorizeGetRequest.class;
	}
}
