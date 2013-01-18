package hemera.ext.oauth.request.flow;

import java.util.Map;

/**
 * <code>FlowAccessPutRequest</code> defines the request
 * for OAuth resource access token action put operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAccessPutRequest extends AbstractFlowAccessRequest {
	/**
	 * The <code>String</code> refresh token.
	 */
	public String refreshToken;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		super.parse(path, arguments);
		// Refresh token.
		this.refreshToken = (String)arguments.get("refresh_token");
		if (this.refreshToken == null || this.refreshToken.trim().isEmpty()) {
			throw new IllegalArgumentException("Refresh Token must be specified.");
		}
		this.refreshToken = this.refreshToken.trim();
	}
}
