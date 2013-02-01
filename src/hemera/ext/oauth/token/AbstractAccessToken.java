package hemera.ext.oauth.token;

/**
 * <code>AbstractAccessToken</code> defines the data
 * structure abstraction for OAuth access token.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractAccessToken extends AbstractConsumerToken {
	/**
	 * The <code>String</code> associated refresh token
	 * value.
	 */
	public final String refreshToken;

	/**
	 * Constructor of <code>AbstractAccessToken</code>.
	 * @param value The <code>String</code> token value.
	 * @param consumerKey The <code>String</code> consumer
	 * key.
	 * @param permissions The <code>String</code> token
	 * permissions.
	 * @param userid The <code>String</code> associated
	 * user ID.
	 * @param expiration The <code>long</code> expiration
	 * time in milliseconds.
	 * @param refreshToken The <code>String</code>
	 * associated refresh token value.
	 */
	protected AbstractAccessToken(final String value, final String consumerKey, final String permissions,
			final String userid, final long expiration, final String refreshToken) {
		super(value, consumerKey, permissions, userid, expiration);
		this.refreshToken = refreshToken;
	}
}
