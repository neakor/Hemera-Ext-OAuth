package hemera.ext.oauth;

/**
 * <code>AccessTokenPair</code> defines the immutable
 * data structure that contains an access token and
 * its paired refresh token.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class AccessTokenPair {
	/**
	 * The <code>String</code> access token.
	 */
	public final String accessToken;
	/**
	 * The <code>String</code> refresh token.
	 */
	public final String refreshToken;
	/**
	 * The <code>long</code> access token expiration
	 * time in milliseconds.
	 */
	public final long accessExpiration;
	/**
	 * The <code>long</code> refresh token expiration
	 * time in milliseconds.
	 */
	public final long refreshExpiration;
	
	/**
	 * Constructor of <code>AccessTokenPair</code>.
	 * @param accessToken The <code>String</code> access
	 * token value.
	 * @param refreshToken The <code>String</code> paired
	 * refresh token.
	 * @param accessExpiration The <code>long</code>
	 * access token expiration time in milliseconds.
	 * @param refreshExpiration The <code>long</code>
	 * refresh token expiration time in milliseconds.
	 */
	public AccessTokenPair(final String accessToken, final String refreshToken, final long accessExpiration, final long refreshExpiration) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.accessExpiration = accessExpiration;
		this.refreshExpiration = refreshExpiration;
	}
}
