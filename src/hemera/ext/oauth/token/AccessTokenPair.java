package hemera.ext.oauth.token;

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
	 * The <code>AbstractAccessToken</code>.
	 */
	public final AbstractAccessToken accessToken;
	/**
	 * The <code>AbstractRefreshToken</code>.
	 */
	public final AbstractRefreshToken refreshToken;
	
	/**
	 * Constructor of <code>AccessTokenPair</code>.
	 * @param accessToken The <code>AbstractAccessToken</code>.
	 * @param refreshToken The <code>AbstractRefreshToken</code>.
	 */
	public AccessTokenPair(final AbstractAccessToken accessToken, final AbstractRefreshToken refreshToken) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
}
