package hemera.ext.oauth;

import hemera.utility.security.AESUtils;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Random;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

/**
 * <code>AbstractConsumer</code> defines the abstraction
 * of a data structure that represents a registered
 * consumer. Typically a consumer is either an internal
 * privileged consumer or a third-party consumer. An
 * internal privileged consumer has the privileges to
 * authenticate users via user credentials and issue
 * authorization tokens that authorize access to user's
 * data entries. An internal privileged consumer is
 * the authorization server in OAuth terminology.
 * <p>
 * Implementations of this class must ensure the OAuth
 * specification integrity. More specifically, the
 * implementations must full-fill following requirements:
 * <ul>
 * <li>An authorization token corresponds to a consumer,
 * a set of permissions and a resource owner.</li>
 * <li>A single authorization token can only be used once
 * to exchange for a single access token.</li>
 * <li>There can exist multiple valid authorization
 * tokens at the same time.</li>
 * <li>An access token has an expiration time and is
 * short-lived.</li>
 * <li>An authorization token has an expiration time
 * and is short-lived</li>
 * <li>A single refresh token can only be used once to
 * exchange for a single access token.</li>
 * <li>Authorization token, access token and refresh
 * token are unique and can be used to identify a set
 * of consumer, user ID and permissions</li>
 * </ul>
 * <p>
 * Implementations may use the utility provided by this
 * package, <code>ConsumerDataGenerator</code> to
 * generate consumer key, encryption key and secret. In
 * which case, the consumer key is a 16-character long
 * random string, encryption key is a 32-character long
 * AES 128-bit key seeded with the consumer key, and the
 * secret is the consumer key encrypted using its
 * encryption key.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public abstract class AbstractConsumer {
	/**
	 * The <code>int</code> randomize character count.
	 * This value dictates the randomness and the length
	 * of generated tokens.
	 */
	private static final int RandomCount = 32;
	/**
	 * The <code>String</code> consumer key.
	 */
	public final String key;
	/**
	 * The <code>String</code> registered domain name.
	 */
	public final String domain;
	/**
	 * The <code>String</code> consumer encryption key
	 * used to generate the consumer secret, authorization
	 * token, and the access token. This key is used with
	 * the AES encryption algorithm.
	 */
	public final String encryptionKey;

	/**
	 * Constructor of <code>AbstractConsumer</code>.
	 * @param key The <code>String</code> consumer key.
	 * @param domain The <code>String</code> registered
	 * domain for the consumer.
	 * @param encryptionKey The <code>String</code> key
	 * used to generate the consumer secret, authorization
	 * token, and the access token. This key is used with
	 * the AES encryption algorithm.
	 */
	protected AbstractConsumer(final String key, final String domain, final String encryptionKey) {
		this.key = key;
		this.domain = domain;
		this.encryptionKey = encryptionKey;
	}

	/**
	 * Generates a random encrypted token based on given
	 * seed and encrypted using the consumer's encryption
	 * key.
	 * @param seed The <code>String</code> seed.
	 * @return The <code>String</code> random token.
	 * @throws NoSuchAlgorithmException If AES is not
	 * supported.
	 * @throws NoSuchPaddingException If transformation
	 * contains a padding that is not available.
	 * @throws InvalidKeyException If the consumer's
	 * encryption key is invalid.
	 * @throws IllegalBlockSizeException If the total
	 * input length of the data processed by this cipher
	 * is not a multiple of block size; or if the AES
	 * encryption algorithm is unable to process the
	 * input data provided.
	 * @throws BadPaddingException Should not occur.
	 * @throws UnsupportedEncodingException If UTF-8
	 * encoding is not supported.
	 * @throws DecoderException If hex encoding failed.
	 */
	private String randomToken(final String seed) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, DecoderException {
		final Random random = new Random();
		// Generate a random chunk of string used to randomize the seed.
		String randomChunk = UUID.randomUUID().toString().replace("-", "");
		final int seedLength = seed.length();
		final int randomizeCount = (seedLength>AbstractConsumer.RandomCount) ? AbstractConsumer.RandomCount : seedLength;
		int randomIndex = 0;
		// Iterate through all the characters in the seed, for each
		// character in the seed, randomly decide if a random new
		// character should be used to replace the seed character.
		final StringBuilder chunkBuilder = new StringBuilder();
		for (int i = 0; i < randomizeCount; i++) {
			final boolean replace = random.nextBoolean();
			if (replace) {
				chunkBuilder.append(randomChunk.charAt(randomIndex));
				randomIndex++;
				// If random chunk has all been used, generate a new one.
				if (randomIndex >= 32) {
					randomIndex = 0;
					randomChunk = UUID.randomUUID().toString().replace("-", "");
				}
			} else {
				chunkBuilder.append(seed.charAt(i));
			}
		}
		// If chunk is not 45 characters long, add more.
		// 45 characters generate a good amount of randomness in the result token.
		final int moreCount = 45 - chunkBuilder.length();
		for (int i = 0; i < moreCount; i++) {
			randomChunk = UUID.randomUUID().toString().replace("-", "");
			chunkBuilder.append(randomChunk.charAt(i));
		}
		final String chunk = chunkBuilder.toString();
		final String token = AESUtils.instance.encrypt(chunk, this.encryptionKey);
		return token;
	}

	/**
	 * Verify the given redirect URL is valid.
	 * @param redirectURL The <code>String</code> URL
	 * to verify.
	 * @return <code>true</code> if given URL is valid.
	 * <code>false</code> otherwise.
	 */
	public boolean verifyRedirectURL(final String redirectURL) {
		try {
			final URL url = new URL(redirectURL);
			final String host = url.getHost();
			if (host == null) return false;
			else return this.domain.equalsIgnoreCase(host);
		} catch (final MalformedURLException e) {
			return false;
		}
	}

	/**
	 * Create a new access token based on the given
	 * authorization token if the specified consumer
	 * secret is valid.
	 * <p>
	 * This method should only be used to generate
	 * an access token with the authorization token
	 * flow.
	 * @param consumerSecret The <code>String</code>
	 * consumer secret to validate.
	 * @param authorizationToken The <code>String</code>
	 * authorization token to exchange with.
	 * @return The <code>AccessTokenPair</code> value.
	 * <code>null</code> if either the consumer secret
	 * or the authorization token is invalid.
	 * @throws NoSuchAlgorithmException If AES is not
	 * supported.
	 * @throws NoSuchPaddingException If transformation
	 * contains a padding that is not available.
	 * @throws InvalidKeyException If the consumer's
	 * encryption key is invalid.
	 * @throws IllegalBlockSizeException If the total
	 * input length of the data processed by this cipher
	 * is not a multiple of block size; or if the AES
	 * encryption algorithm is unable to process the
	 * input data provided.
	 * @throws BadPaddingException Should not occur.
	 * @throws UnsupportedEncodingException If UTF-8
	 * encoding is not supported.
	 * @throws SQLException If database access failed.
	 * @throws DecoderException If hex encoding failed.
	 */
	public AccessTokenPair newAccessToken(final String consumerSecret, final String authorizationToken) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SQLException, DecoderException {
		// Verify consumer secret.
		final boolean secretValid = this.verifySecret(consumerSecret);
		if (!secretValid) return null;
		// Verify authorization token.
		final boolean authorizationTokenValid = this.verifyAuthorizationToken(authorizationToken);
		if (!authorizationTokenValid) return null;
		// Decrypt authorization token. The decrypted value is
		// the consumer key, permissions and random chunk.
		final String decrypted = AESUtils.instance.decrypt(authorizationToken, this.encryptionKey);
		// Generate new access token.
		final String accessToken = this.randomToken(decrypted);
		// Generate a paired refresh token.
		final String refreshToken = this.randomToken(decrypted);
		// Associate access token with authorization token.
		final long currentTime = System.currentTimeMillis();
		final long accessExpiration = currentTime + this.getAccessTokenLifetime();
		final long refreshExpiration = currentTime + this.getRefreshTokenLifetime();
		final boolean succeeded = this.associateAccessTokenPair(accessToken, refreshToken, authorizationToken, accessExpiration, refreshExpiration);
		if (succeeded) return new AccessTokenPair(accessToken, refreshToken, accessExpiration, refreshExpiration);
		// Concurrent duplicate associations.
		else return null;
	}

	/**
	 * Create a new access token if the specified
	 * consumer secret is valid and this consumer has
	 * the client credentials flow privilege.
	 * <p>
	 * This method should only be used to generate
	 * an access token with the client credentials
	 * flow.
	 * @param consumerSecret The <code>String</code>
	 * consumer secret to validate.
	 * @param userid The <code>String</code> ID of the
	 * user granting the permission.
	 * @param permission The <code>String</code>
	 * permission to grant to the consumer.
	 * @return The <code>AccessTokenPair</code> value.
	 * <code>null</code> if either the consumer secret
	 * is invalid or the consumer does not have the
	 * client credentials flow privilege.
	 * @throws NoSuchAlgorithmException If AES is not
	 * supported.
	 * @throws NoSuchPaddingException If transformation
	 * contains a padding that is not available.
	 * @throws InvalidKeyException If the consumer's
	 * encryption key is invalid.
	 * @throws IllegalBlockSizeException If the total
	 * input length of the data processed by this cipher
	 * is not a multiple of block size; or if the AES
	 * encryption algorithm is unable to process the
	 * input data provided.
	 * @throws BadPaddingException Should not occur.
	 * @throws UnsupportedEncodingException If UTF-8
	 * encoding is not supported.
	 * @throws SQLException If database access failed.
	 * @throws DecoderException If hex encoding failed.
	 */
	public AccessTokenPair newAccessToken(final String consumerSecret, final String userid, final String permission) throws NoSuchAlgorithmException,
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SQLException, DecoderException {
		// Verify consumer secret.
		final boolean secretValid = this.verifySecret(consumerSecret);
		if (!secretValid) return null;
		// Verify privilege.
		if (!this.hasClientCredentialsFlowPrivilege()) return null;
		// Use consumer key and client credentials flow permission as seed.
		final String seed = this.key+permission;
		// Generate new access token.
		final String accessToken = this.randomToken(seed);
		// Generate a paired refresh token.
		final String refreshToken = this.randomToken(seed);
		// Associate access token with user and permission.
		final long currentTime = System.currentTimeMillis();
		final long accessExpiration = currentTime + this.getAccessTokenLifetime();
		final long refreshExpiration = currentTime + this.getRefreshTokenLifetime();
		final boolean succeeded = this.associateAccessTokenPair(accessToken, refreshToken, userid, permission, accessExpiration, refreshExpiration);
		if (succeeded) return new AccessTokenPair(accessToken, refreshToken, accessExpiration, refreshExpiration);
		// Concurrent duplicate associations.
		else return null;
	}

	/**
	 * Exchange for a new access token using the given
	 * refresh token if the specified consumer secret
	 * is valid. This method invalidates the previous
	 * access token associated with the given refresh
	 * token.
	 * @param consumerSecret The <code>String</code>
	 * consumer secret to validate.
	 * @param refreshToken The <code>String</code>
	 * refresh token associated with a previous access
	 * token to exchange with.
	 * @return The new <code>AccessTokenPair</code>.
	 * <code>null</code> if either the consumer secret
	 * or the refresh token is invalid.
	 * @throws NoSuchAlgorithmException If AES is not
	 * supported.
	 * @throws NoSuchPaddingException If transformation
	 * contains a padding that is not available.
	 * @throws InvalidKeyException If the consumer's
	 * encryption key is invalid.
	 * @throws IllegalBlockSizeException If the total
	 * input length of the data processed by this cipher
	 * is not a multiple of block size; or if the AES
	 * encryption algorithm is unable to process the
	 * input data provided.
	 * @throws BadPaddingException Should not occur.
	 * @throws UnsupportedEncodingException If UTF-8
	 * encoding is not supported.
	 * @throws SQLException If database access failed.
	 * @throws DecoderException If hex encoding failed.
	 */
	public AccessTokenPair refreshAccessToken(final String consumerSecret, final String refreshToken) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SQLException, DecoderException {
		// Verify consumer secret.
		final boolean secretValid = this.verifySecret(consumerSecret);
		if (!secretValid) return null;
		// Verify refresh token.
		final boolean refreshTokenValid = this.verifyRefreshToken(refreshToken);
		if (!refreshTokenValid) return null;
		// Invalidate previous access token.
		this.invalidateAccessToken(refreshToken);
		// Generate new access token.
		final String accessToken = this.randomToken(refreshToken);
		// Generate a paired refresh token.
		final String newRefreshToken = this.randomToken(accessToken);
		// Associate access token with user and permissions.
		final long currentTime = System.currentTimeMillis();
		final long accessExpiration = currentTime + this.getAccessTokenLifetime();
		final long refreshExpiration = currentTime + this.getRefreshTokenLifetime();
		final boolean succeeded = this.associateAccessTokenPairRefresh(accessToken, newRefreshToken, refreshToken, accessExpiration, refreshExpiration);
		if (succeeded) return new AccessTokenPair(accessToken, newRefreshToken, accessExpiration, refreshExpiration);
		// Concurrent duplicate associations.
		else return null;
	}

	/**
	 * Verify the given consumer secret. A consumer's
	 * secret should be the consumer's key encrypted
	 * using its encryption key.
	 * @param consumerSecret The <code>String</code>
	 * value to verify.
	 * @return <code>true</code> if the given value
	 * is valid. <code>false</code> otherwise.
	 */
	public boolean verifySecret(final String consumerSecret) {
		try {
			// Decrypt given secret with encryption key.
			final String decrypted = AESUtils.instance.decrypt(consumerSecret, this.encryptionKey);
			// Compare decrypted value with consumer key.
			return this.key.equals(decrypted);
		} catch (final Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Verify the given refresh token.
	 * <p>
	 * This method should verify that the given token
	 * exists, has not been used to exchange for a new
	 * access token, and is associated with an access
	 * token that is associated with this consumer.
	 * @param refreshToken The <code>String</code>
	 * token to verify.
	 * @return <code>true</code> if the given token is
	 * valid. <code>false</code> otherwise.
	 * @throws SQLException If database access failed.
	 */
	protected abstract boolean verifyRefreshToken(final String refreshToken) throws SQLException;

	/**
	 * Verify the given authorization token.
	 * <p>
	 * This method should verify that the given token
	 * exists, has not been used, is associated with
	 * this consumer, and has not expired.
	 * @param authorizationToken The <code>String</code>
	 * token to verify.
	 * @return <code>true</code> if the given token is
	 * valid. <code>false</code> otherwise.
	 * @throws SQLException If database access failed.
	 */
	protected abstract boolean verifyAuthorizationToken(final String authorizationToken) throws SQLException;

	/**
	 * Invalidate the access token associated with the
	 * given refresh token.
	 * @param refreshToken The <code>String</code>
	 * refresh token used to identify the access token.
	 * @throws SQLException If database access failed.
	 */
	protected abstract void invalidateAccessToken(final String refreshToken) throws SQLException;

	/**
	 * Associate the given new access token and the
	 * refresh token pair with the user and permissions
	 * identified by the given authorization token with
	 * this consumer.
	 * <p>
	 * This method must ensure that the authorization
	 * token is only associated with a single access
	 * token. Concurrent associations should only allow
	 * one to succeed. By the end of this method logic
	 * execution, the authorization token should be
	 * marked as used to prevent further use of the same
	 * authorization token.
	 * <p>
	 * The access token and refresh token given to this
	 * method are guaranteed to be unique.
	 * <p>
	 * This method is only used in the authorization
	 * token flow.
	 * @param accessToken The <code>String</code> access
	 * token to associate.
	 * @param refreshToken The <code>String</code> paired
	 * refresh token.
	 * @param authorizationToken The <code>String</code>
	 * authorization token used to identify the user
	 * and permissions.
	 * @param accessExpiration The <code>long</code>
	 * server time in milliseconds when the access token
	 * should expire.
	 * @param refreshExpiration The <code>long</code>
	 * server time in milliseconds when the refresh token
	 * should expire.
	 * @return <code>true</code> if association succeeded.
	 * <code>false</code> if the authorization token
	 * is already associated with another access token.
	 * @throws SQLException If database access failed.
	 */
	protected abstract boolean associateAccessTokenPair(final String accessToken, final String refreshToken, final String authorizationToken,
			final long accessExpiration, final long refreshExpiration) throws SQLException;

	/**
	 * Associate the given new access token and the
	 * refresh token pair with the given user and
	 * permission with this consumer.
	 * <p>
	 * The access token and refresh token given to this
	 * method are guaranteed to be unique.
	 * <p>
	 * This method is only used in the client credentials
	 * token flow.
	 * @param accessToken The <code>String</code> access
	 * token to associate.
	 * @param refreshToken The <code>String</code> paired
	 * refresh token.
	 * @param userid The <code>String</code> ID of the
	 * user granting the permission.
	 * @param permission The <code>String</code>
	 * permission to grant to the consumer.
	 * @param accessExpiration The <code>long</code>
	 * server time in milliseconds when the access token
	 * should expire.
	 * @param refreshExpiration The <code>long</code>
	 * server time in milliseconds when the refresh token
	 * should expire.
	 * @return <code>true</code> if association succeeded.
	 * <code>false</code> if any processing failed.
	 * @throws SQLException If database access failed.
	 */
	protected abstract boolean associateAccessTokenPair(final String accessToken, final String refreshToken, final String userid, final String permission,
			final long accessExpiration, final long refreshExpiration) throws SQLException;

	/**
	 * Associate the given new access token and the
	 * refresh token pair with the user and permissions
	 * identified by the given old refresh token with
	 * this consumer.
	 * <p>
	 * This method must ensure that the old refresh
	 * token is only associated with a single access
	 * token. Concurrent associations should only allow
	 * one to succeed.
	 * <p>
	 * The access token and refresh token given to this
	 * method are guaranteed to be unique.
	 * @param accessToken The <code>String</code> access
	 * token to associate.
	 * @param refreshToken The <code>String</code> paired
	 * refresh token.
	 * @param oldRefreshToken The <code>String</code>
	 * authorization token used to identify the user
	 * and permissions.
	 * @param accessExpiration The <code>long</code>
	 * server time in milliseconds when the access token
	 * should expire.
	 * @param refreshExpiration The <code>long</code>
	 * server time in milliseconds when the refresh token
	 * should expire.
	 * @return <code>true</code> if association succeeded.
	 * <code>false</code> if the old refresh token is
	 * already associated with another access token.
	 * @throws SQLException If database access failed.
	 */
	protected abstract boolean associateAccessTokenPairRefresh(final String accessToken, final String refreshToken, final String oldRefreshToken,
			final long accessExpiration, final long refreshExpiration) throws SQLException;

	/**
	 * Generate a new authorization token for this
	 * consumer with specified permissions associated
	 * with the user with given ID.
	 * @param permissions The <code>String</code> of
	 * the permissions requested.
	 * @param userid The <code>String</code> ID of the
	 * user granting the permissions.
	 * @return The <code>String</code> authorization
	 * token newly generated.
	 * @throws NoSuchAlgorithmException If AES is not
	 * supported.
	 * @throws NoSuchPaddingException If transformation
	 * contains a padding that is not available.
	 * @throws InvalidKeyException If the consumer's
	 * encryption key is invalid.
	 * @throws IllegalBlockSizeException If the total
	 * input length of the data processed by this cipher
	 * is not a multiple of block size; or if the AES
	 * encryption algorithm is unable to process the
	 * input data provided.
	 * @throws BadPaddingException Should not occur.
	 * @throws UnsupportedEncodingException If UTF-8
	 * encoding is not supported.
	 * @throws SQLException If associating authorization
	 * token failed.
	 * @throws DecoderException If hex encoding failed.
	 */
	public String newAuthorizationToken(final String permissions, final String userid) throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SQLException, DecoderException {
		// Generate a token chunk based on consumer data and resource grant.
		final String token = this.randomToken(this.key+permissions);
		final long expiration = System.currentTimeMillis() + this.getAuthorizationTokenLifetime();
		this.associateAuthorizationToken(token, permissions, userid, expiration);
		return token;
	}

	/**
	 * Associate the new authorization token with the
	 * given permissions of the granting user with the
	 * given user ID with this consumer.
	 * <p>
	 * The authorization token given to this method is
	 * guaranteed to be unique.
	 * @param token The <code>String</code> authorization
	 * token.
	 * @param permissions The <code>String</code> of
	 * permissions granted.
	 * @param userid The <code>String</code> ID of the
	 * user granted permissions.
	 * @param expiration The <code>long</code> server
	 * time in milliseconds when the token should expire.
	 * @throws SQLException If query execution failed.
	 */
	protected abstract void associateAuthorizationToken(final String token, final String permissions, final String userid,
			final long expiration) throws SQLException;

	/**
	 * Retrieve the lifetime duration of access tokens.
	 * @return The <code>long</code> life time in
	 * milliseconds.
	 */
	protected abstract long getAccessTokenLifetime();
	
	/**
	 * Retrieve the lifetime duration of refresh tokens.
	 * @return The <code>long</code> life time in
	 * milliseconds.
	 */
	protected abstract long getRefreshTokenLifetime();
	
	/**
	 * Retrieve the lifetime duration of authorization
	 * tokens.
	 * @return The <code>long</code> life time in
	 * milliseconds.
	 */
	protected abstract long getAuthorizationTokenLifetime();

	/**
	 * Retrieve the valid authorization token associated
	 * with this consumer for the user with given user
	 * ID for the specified permissions.
	 * <p>
	 * A valid authorization token is one that has not
	 * been used to exchange for an access token yet,
	 * nor has it expired.
	 * @param permissions The <code>String</code> of
	 * the permissions requested.
	 * @param userid The <code>String</code> ID of the
	 * user granting the permissions.
	 * @return The <code>String</code> authorization
	 * token. <code>null</code> if there is none or the
	 * authorization token has been used to exchange an
	 * access token already.
	 * @throws SQLException If database access failed.
	 */
	public abstract String getValidAuthorizationToken(final String permissions, final String userid) throws SQLException;
	
	/**
	 * Check if the consumer has user authorization
	 * privilege to issue authorization tokens on
	 * behalf of the user.
	 * @return <code>true</code> if the consumer has
	 * such privilege. <code>false</code> otherwise.
	 */
	public abstract boolean hasUserAuthorizationPrivilege();
	
	/**
	 * Check if the consumer has user authentication
	 * privilege to authenticate a user via user's
	 * credentials.
	 * @return <code>true</code> if the consumer has
	 * such privilege. <code>false</code> otherwise.
	 */
	public abstract boolean hasUserAuthenticationPrivilege();
	
	/**
	 * Check if the consumer has client credentials
	 * flow privilege that allows the consumer to obtain
	 * all permissions over a user's data without the
	 * need to go through the user authorization process.
	 * @return <code>true</code> if the consumer has
	 * such privilege. <code>false</code> otherwise.
	 */
	public abstract boolean hasClientCredentialsFlowPrivilege();
}
