package hemera.ext.oauth.util;

/**
 * <code>ConsumerData</code> defines the immutable
 * data structure holding a consumer's key and its
 * encryption key.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class ConsumerData {
	/**
	 * The <code>String</code> consumer key.
	 */
	public final String key;
	/**
	 * The <code>String</code> encryption key.
	 */
	public final String encryptionKey;
	/**
	 * The <code>String</code> secret.
	 */
	public final String secret;
	
	/**
	 * Constructor of <code>ConsumerData</code>.
	 * @param key The <code>String</code> consumer key.
	 * @param encryptionKey The <code>String</code>
	 * encryption key.
	 * @param secret The <code>String</code> secret.
	 */
	ConsumerData(final String key, final String encryptionKey, final String secret) {
		this.key = key;
		this.encryptionKey = encryptionKey;
		this.secret = secret;
	}
}
