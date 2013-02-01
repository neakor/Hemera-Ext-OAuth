package hemera.ext.oauth.token;

/**
 * <code>AbstractAuthorizationToken</code> defines the
 * data structure abstraction for authorization token.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractAuthorizationToken extends AbstractConsumerToken {

	/**
	 * Constructor of <code>AbstractAuthorizationToken</code>.
	 * @param value The <code>String</code> token value.
	 * @param consumerKey The <code>String</code> consumer
	 * key.
	 * @param permissions The <code>String</code> token
	 * permissions.
	 * @param userid The <code>String</code> associated
	 * user ID.
	 * @param expiration The <code>long</code> expiration
	 * time in milliseconds.
	 */
	protected AbstractAuthorizationToken(final String value, final String consumerKey, final String permissions,
			final String userid, final long expiration) {
		super(value, consumerKey, permissions, userid, expiration);
	}
}
