package hemera.ext.oauth.response.flow;

import org.json.JSONObject;

import hemera.core.structure.AbstractResponse;
import hemera.core.structure.enumn.EHttpStatus;

/**
 * <code>FlowAuthorizeResponse</code> defines the OAuth
 * resource authorize action get and post operations.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public final class FlowAuthorizeResponse extends AbstractResponse {
	/**
	 * The <code>String</code> authorization token.
	 */
	private final String authorizationToken;
	
	/**
	 * Constructor of <code>AuthorizationResponse</code>.
	 * @param token The <code>String</code> authorization
	 * token.
	 */
	public FlowAuthorizeResponse(final String token) {
		this.authorizationToken = token;
		if (this.authorizationToken == null) {
			throw new IllegalArgumentException("A valid authorization token must be specified for a success response.");
		}
	}
	
	/**
	 * Constructor of <code>AuthorizationResponse</code>.
	 * @param status The error <code>EHttpStatus</code>.
	 * @param error The <code>String</code> error message.
	 */
	public FlowAuthorizeResponse(final EHttpStatus status, final String error) {
		super(status, error);
		this.authorizationToken = null;
	}

	@Override
	protected void insertData(final JSONObject data) throws Exception {
		data.put("authorization_token", this.authorizationToken);
	}
}
