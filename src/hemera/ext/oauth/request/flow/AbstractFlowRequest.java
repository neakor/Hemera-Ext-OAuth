package hemera.ext.oauth.request.flow;

import java.util.Map;

import hemera.core.structure.interfaces.IRequest;

/**
 * <code>AbstractFlowRequest</code> defines the request
 * abstraction for the OAuth authorization flows.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractFlowRequest implements IRequest {
	/**
	 * The <code>String</code> key of the requesting
	 * consumer.
	 */
	public String consumerKey;
	/**
	 * The <code>String</code> redirect URL.
	 */
	public String redirectURL;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		// Consumer key.
		this.consumerKey = (String)arguments.get("consumer_key");
		if (this.consumerKey == null || this.consumerKey.trim().isEmpty()) {
			throw new IllegalArgumentException("Consumer key must be specified.");
		}
		this.consumerKey = this.consumerKey.trim();
		// Redirect URL.
		this.redirectURL = (String)arguments.get("redirect_url");
		if (this.redirectURL == null || this.redirectURL.trim().isEmpty()) {
			throw new IllegalArgumentException("Redirect URL must be specified.");
		}
		this.redirectURL = this.redirectURL.trim();
	}
}
