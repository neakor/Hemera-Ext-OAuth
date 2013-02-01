package hemera.ext.oauth.token;

import java.sql.SQLException;

/**
 * <code>AbstractToken</code> defines the abstraction
 * of all types of tokens.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
abstract class AbstractToken implements IToken {
	/**
	 * The <code>String</code> token value.
	 */
	public final String value;
	/**
	 * The <code>long</code> expiration time in milli-
	 * seconds.
	 */
	private volatile long expiration;
	
	/**
	 * Constructor of <code>AbstractToken</code>.
	 * @param value The <code>String</code> token value.
	 * @param expiration The <code>long</code> expiration
	 * time in milliseconds.
	 */
	AbstractToken(final String value, final long expiration) {
		this.value = value;
		this.expiration = expiration;
	}

	@Override
	public final void invalidate() throws SQLException {
		this.expiration = Long.MIN_VALUE;
		this.setExpiration(this.expiration);
	}
	
	/**
	 * Set the expiration value of this token to the
	 * given value.
	 * @param value The <code>long</code> expiration
	 * value in milliseconds.
	 * @throws SQLException If database access failed.
	 */
	protected abstract void setExpiration(final long value) throws SQLException;
	
	/**
	 * Retrieve the token's expiration time.
	 * @return The <code>long</code> expiration time in
	 * milliseconds.
	 */
	public long getExpiration() {
		return this.expiration;
	}

	@Override
	public final boolean isValid() {
		return (this.expiration > System.currentTimeMillis());
	}
}
