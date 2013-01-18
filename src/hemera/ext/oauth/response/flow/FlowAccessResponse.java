package hemera.ext.oauth.response.flow;

import org.json.JSONObject;

import hemera.core.structure.AbstractResponse;
import hemera.core.structure.enumn.EHttpStatus;

/**
 * <code>FlowAccessResponse</code> defines the response
 * for OAuth resource access token action all operations.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAccessResponse extends AbstractResponse {
	/**
	 * The <code>String</code> access token.
	 */
	private final String accessToken;
	/**
	 * The <code>String</code> refresh token.
	 */
	private final String refreshToken;
	/**
	 * The <code>long</code> access token expiration time
	 * in milliseconds.
	 */
	private final long expiration;
	
	/**
	 * Constructor of <code>FlowAccessResponse</code>.
	 * @param accessToken The <code>String</code> access
	 * token.
	 * @param refreshToken The <code>String</code> refresh
	 * token.
	 * @param expiration The <code>long</code> access
	 * token expiration time in milliseconds.
	 */
	public FlowAccessResponse(final String accessToken, final String refreshToken, final long expiration) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		if (this.accessToken == null) {
			throw new IllegalArgumentException("A valid access token must be specified for a success response.");
		}
		if (this.refreshToken == null) {
			throw new IllegalArgumentException("A valid refresh token must be specified for a success response.");
		}
		this.expiration = expiration;
	}
	
	/**
	 * Constructor of <code>AccessTokenResponse</code>.
	 * @param status The error <code>EHttpStatus</code>.
	 * @param error The <code>String</code> error message.
	 */
	public FlowAccessResponse(final EHttpStatus status, final String error) {
		super(status, error);
		this.accessToken = null;
		this.refreshToken = null;
		this.expiration = Long.MIN_VALUE;
	}

	@Override
	protected void insertData(final JSONObject data) throws Exception {
		data.put("access_token", this.accessToken);
		data.put("refresh_token", this.refreshToken);
		data.put("expiration", this.expiration);
	}
}
