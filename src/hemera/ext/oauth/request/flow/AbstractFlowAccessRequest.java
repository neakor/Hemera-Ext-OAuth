package hemera.ext.oauth.request.flow;

import java.util.Map;

/**
 * <code>AbstractFlowAccessRequest</code> defines the
 * request abstraction for OAuth resource access token
 * action put and post operations.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowAccessRequest extends AbstractFlowRequest {
	/**
	 * The <code>String</code> consumer secret.
	 */
	public String consumerSecret;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		super.parse(path, arguments);
		// Consumer secret.
		this.consumerSecret = (String)arguments.get("consumer_secret");
		if (this.consumerSecret == null || this.consumerSecret.trim().isEmpty()) {
			throw new IllegalArgumentException("Consumer secret must be specified.");
		}
		this.consumerSecret = this.consumerSecret.trim();
	}
}
