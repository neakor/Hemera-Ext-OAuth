package hemera.ext.oauth.unittest;

import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.token.AbstractAccessToken;
import hemera.ext.oauth.token.AbstractAuthorizationToken;
import hemera.ext.oauth.token.AbstractRefreshToken;
import hemera.ext.oauth.token.AccessTokenPair;

import java.sql.SQLException;

public class TestTokenRandomness {

	private static final String permissions = "data_write,data_read,super,adsfkjashdfjkhsf";
	private static final String userid = "d92f98b5693243b3a1c312ea3bf4942b";
	
	public static void main(String[] args) throws Exception {
		final String secret = "983de8bd221c056d7ab2b723f67a333c94d428e9a74cd0c25b30a868464f739f";
		final Consumer consumer = new Consumer("6e591afe5374410b", "localhost", "58af94d5c748d8365eb6bf24abde23ef");
		for (int i = 0; i < 10; i++) {
			final AbstractAuthorizationToken authToken = consumer.newAuthorizationToken(permissions, userid);
			System.out.println("Auth token:    " + authToken);
			final AccessTokenPair accessToken = consumer.newAccessToken(secret, authToken);
			System.out.println("Access token   " + accessToken.accessToken);
			System.out.println("Refresh token  " + accessToken.refreshToken);
			final AccessTokenPair accessToken2 = consumer.refreshAccessToken(secret, accessToken.refreshToken);
			System.out.println("Access token2  " + accessToken2.accessToken);
			System.out.println("Refresh token2 " + accessToken2.refreshToken);
			final AccessTokenPair accessToken3 = consumer.refreshAccessToken(secret, accessToken2.refreshToken);
			System.out.println("Access token3  " + accessToken3.accessToken);
			System.out.println("Refresh token3 " + accessToken3.refreshToken);
			System.out.println(accessToken3.accessToken.value.length());
		}
	}

	private static class Consumer extends AbstractConsumer {

		protected Consumer(String key, String domain, String encryptionKey) {
			super(key, domain, encryptionKey);
		}

		@Override
		protected boolean verifyRefreshToken(String refreshToken) throws SQLException {
			return true;
		}

		@Override
		protected void invalidateAccessToken(String refreshToken) throws SQLException {
		}

		@Override
		protected boolean associateAccessTokenPairRefresh(String accessToken, String refreshToken, String oldRefreshToken, long accessExpiration,
				long refreshExporation) throws SQLException {
			return true;
		}

		@Override
		protected long getAccessTokenLifetime() {
			return 10000;
		}
		
		@Override
		protected long getRefreshTokenLifetime() {
			return 10000;
		}

		@Override
		protected long getAuthorizationTokenLifetime() {
			return 10000;
		}

		@Override
		public AbstractAuthorizationToken getValidAuthorizationToken(String permissions, String userid) throws SQLException {
			return null;
		}

		@Override
		public boolean hasUserAuthorizationPrivilege() {
			return true;
		}

		@Override
		public boolean hasUserAuthenticationPrivilege() {
			return true;
		}

		@Override
		public boolean hasClientCredentialsFlowPrivilege() {
			return true;
		}

		@Override
		protected AbstractAuthorizationToken insertAuthorizationToken(
				String value, String permissions, String userid, long expiration)
				throws SQLException {
			return new AuthorizationToken(value, this.key, permissions, userid, expiration);
		}

		@Override
		protected AbstractRefreshToken insertRefreshToken(String value,
				String accessTokenValue, long expiration) throws SQLException {
			return new RefreshToken(value, expiration, accessTokenValue, this);
		}

		@Override
		protected AbstractAccessToken insertAccessToken(String value,
				AbstractRefreshToken refreshToken, String permissions,
				String userid, long expiration) throws SQLException {
			return new AccessToken(value, this.key, permissions, userid, expiration, refreshToken.value);
		}
	}
	
	private static class AuthorizationToken extends AbstractAuthorizationToken {

		protected AuthorizationToken(String value, String consumerKey,
				String permissions, String userid, long expiration) {
			super(value, consumerKey, permissions, userid, expiration);
		}

		@Override
		protected void setExpiration(long value) throws SQLException {
			
		}
	}
	
	private static class RefreshToken extends AbstractRefreshToken {
		private final Consumer consumer;

		protected RefreshToken(String value, long expiration, String accessToken, final Consumer consumer) {
			super(value, expiration, accessToken);
			this.consumer = consumer;
		}

		@Override
		public AbstractAccessToken getAssociatedAccessToken()
				throws SQLException {
			return new AccessToken(this.accessToken, this.consumer.key, permissions, userid, this.getExpiration(), this.value);
		}

		@Override
		protected void setExpiration(long value) throws SQLException {
			
		}
	}
	
	private static class AccessToken extends AbstractAccessToken {

		protected AccessToken(String value, String consumerKey,
				String permissions, String userid, long expiration,
				String refreshToken) {
			super(value, consumerKey, permissions, userid, expiration, refreshToken);
		}

		@Override
		protected void setExpiration(long value) throws SQLException {
			
		}
	}
}
