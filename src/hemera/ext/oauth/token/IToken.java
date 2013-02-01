package hemera.ext.oauth.token;

/**
 * <code>IToken</code> defines the interface for all
 * types of OAuth tokens.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public interface IToken {

	/**
	 * Invalidate this token.
	 * @throws Exception If any processing failed.
	 */
	public void invalidate() throws Exception;
	
	/**
	 * Check if the token is valid.
	 * @return <code>true</code> if the token is valid.
	 * <code>false</code> otherwise.
	 */
	public boolean isValid();
}
