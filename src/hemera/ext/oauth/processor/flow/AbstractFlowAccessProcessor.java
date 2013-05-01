package hemera.ext.oauth.processor.flow;

import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.request.flow.AbstractFlowAccessRequest;
import hemera.ext.oauth.response.flow.FlowAccessResponse;

/**
 * <code>AbstractFlowAccessProcessor</code> defines
 * the processor abstraction for OAuth resource access
 * token action all operations.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.1
 */
abstract class AbstractFlowAccessProcessor<RQ extends AbstractFlowAccessRequest, C extends AbstractConsumer>
extends AbstractFlowProcessor<RQ, FlowAccessResponse, C> {

	@Override
	protected FlowAccessResponse noSuchConsumerResponse(final RQ request) {
		return new FlowAccessResponse(EHttpStatus.C404_NotFound, "There is no such consumer.");
	}

	@Override
	protected FlowAccessResponse invalidRedirectURLResponse(final RQ request) {
		return new FlowAccessResponse(EHttpStatus.C417_ExpectationFailed, "Invalid redirect URL.");
	}

	@Override
	protected FlowAccessResponse exceptionResponse(final RQ request, final Exception e) {
		return new FlowAccessResponse(EHttpStatus.C500_InternalServerError, e.getMessage());
	}
}
