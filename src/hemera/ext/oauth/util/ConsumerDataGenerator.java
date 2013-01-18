package hemera.ext.oauth.util;

import hemera.utility.security.AESUtils;

import java.util.UUID;

/**
 * <code>ConsumerDataGenerator</code> defines the utility
 * singleton that generates <code>ConsumerData</code>.
 * This utility generates consumer's key as a 16-character
 * long random string, encryption key as a 32-character
 * long AES 128-bit key seeded with the consumer key, and
 * the secret is the consumer key encrypted using its
 * encryption key.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public enum ConsumerDataGenerator {
	/**
	 * The singleton instance.
	 */
	instance;

	/**
	 * Generate a new consumer data.
	 * @return The <code>ConsumerData</code> instance.
	 * @throws Exception If encryption failed.
	 */
	public ConsumerData newData() throws Exception {
		// Random key.
		final String key = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
		// Generate encryption key using consumer key.
		final String encryptionKey = AESUtils.instance.generateKey(key, 128);
		// Encryption key to generate secret.
		final String secret = AESUtils.instance.encrypt(key, encryptionKey);
		return new ConsumerData(key, encryptionKey, secret);
	}
}
