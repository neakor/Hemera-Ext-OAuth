package hemera.ext.oauth.request.flow;

import java.util.Map;

/**
 * <code>FlowAccessPostRequest</code> defines the request
 * for OAuth resource access token action post operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAccessPostRequest extends AbstractFlowAccessRequest {
	/**
	 * The <code>String</code> authorization token.
	 */
	public String authorizationToken;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		super.parse(path, arguments);
		// Authorization token.
		this.authorizationToken = (String)arguments.get("authorization_token");
		if (this.authorizationToken == null || this.authorizationToken.trim().isEmpty()) {
			throw new IllegalArgumentException("Authorization Token must be specified.");
		}
		this.authorizationToken = this.authorizationToken.trim();
	}
}
