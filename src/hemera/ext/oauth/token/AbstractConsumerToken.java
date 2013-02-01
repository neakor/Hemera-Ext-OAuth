package hemera.ext.oauth.token;

/**
 * <code>AbstractConsumerToken</code> defines the data
 * structure abstraction for tokens that contain the
 * associated consumer data.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
abstract class AbstractConsumerToken extends AbstractToken {
	/**
	 * The <code>String</code> consumer key.
	 */
	public final String consumerKey;
	/**
	 * The <code>String</code> permissions.
	 */
	public final String permissions;
	/**
	 * The <code>String</code> associated user ID.
	 */
	public final String userid;

	/**
	 * Constructor of <code>AbstractConsumerToken</code>.
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
	AbstractConsumerToken(final String value, final String consumerKey, final String permissions,
			final String userid, final long expiration) {
		super(value, expiration);
		this.consumerKey = consumerKey;
		this.permissions = permissions;
		this.userid = userid;
	}
}
