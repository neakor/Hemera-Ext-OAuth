package hemera.ext.oauth.response.flow;

import org.json.JSONObject;

import hemera.core.structure.AbstractResponse;
import hemera.core.structure.enumn.EHttpStatus;
import hemera.ext.oauth.token.AccessTokenPair;

/**
 * <code>FlowAccessResponse</code> defines the response
 * for OAuth resource access token action all operations.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAccessResponse extends AbstractResponse {
	/**
	 * The <code>AccessTokenPair</code>.
	 */
	private final AccessTokenPair pair;
	
	/**
	 * Constructor of <code>FlowAccessResponse</code>.
	 * @param pair The <code>AccessTokenPair</code>.
	 */
	public FlowAccessResponse(final AccessTokenPair pair) {
		this.pair = pair;
		if (this.pair == null) {
			throw new IllegalArgumentException("A valid access token pair must be specified for a success response.");
		}
	}
	
	/**
	 * Constructor of <code>AccessTokenResponse</code>.
	 * @param status The error <code>EHttpStatus</code>.
	 * @param error The <code>String</code> error message.
	 */
	public FlowAccessResponse(final EHttpStatus status, final String error) {
		super(status, error);
		this.pair = null;
	}

	@Override
	protected void insertData(final JSONObject data) throws Exception {
		data.put("access_token", this.pair.accessToken.value);
		data.put("access_expiration", this.pair.accessToken.getExpiration());
		data.put("refresh_token", this.pair.refreshToken.value);
		data.put("refresh_expiration", this.pair.refreshToken.getExpiration());
	}
}
