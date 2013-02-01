package hemera.ext.oauth.token;

import java.sql.SQLException;

/**
 * <code>AbstractRefreshToken</code> defines the data
 * structure abstraction for refresh token.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractRefreshToken extends AbstractToken {
	/**
	 * The <code>String</code> associated access token
	 * value.
	 */
	public final String accessToken;

	/**
	 * Constructor of <code>AbstractRefreshToken</code>.
	 * @param value The <code>String</code> token value.
	 * @param expiration The <code>long</code> expiration
	 * time in milliseconds.
	 * @param accessToken The <code>String</code>
	 * associated access token value.
	 */
	protected AbstractRefreshToken(final String value, final long expiration, final String accessToken) {
		super(value, expiration);
		this.accessToken = accessToken;
	}
	
	/**
	 * Retrieve the associated access token.
	 * @return The <code>AbstractAccessToken</code>.
	 * @throws SQLException if database access failed.
	 */
	public abstract AbstractAccessToken getAssociatedAccessToken() throws SQLException;
}
