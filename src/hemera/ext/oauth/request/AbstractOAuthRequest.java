package hemera.ext.oauth.request;

import java.util.Map;

import hemera.core.structure.interfaces.IRequest;

/**
 * <code>AbstractOAuthRequest</code> defines the base
 * abstraction of all requests that access resources
 * using a granted OAuth access token.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractOAuthRequest implements IRequest {
	/**
	 * The <code>String</code> OAuth access token.
	 */
	public String accessToken;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		this.accessToken = (String)arguments.get("access_token");
		if (this.accessToken == null || this.accessToken.trim().isEmpty()) {
			throw new IllegalArgumentException("Unauthorized request. OAuth access token must be specified.");
		}
		this.accessToken = this.accessToken.trim();
	}
}
