package hemera.ext.oauth.unittest;

import hemera.ext.oauth.AbstractConsumer;
import hemera.ext.oauth.AccessTokenPair;

import java.sql.SQLException;
import java.util.UUID;

public class TestTokenRandomness {

	public static void main(String[] args) throws Exception {
		final String userid = UUID.randomUUID().toString().replace("-", "");
		final String secret = "983de8bd221c056d7ab2b723f67a333c94d428e9a74cd0c25b30a868464f739f";
		final Consumer consumer = new Consumer("6e591afe5374410b", "localhost", "58af94d5c748d8365eb6bf24abde23ef");
		for (int i = 0; i < 10; i++) {
			final String authToken = consumer.newAuthorizationToken("data_write,data_read,super,adsfkjashdfjkhsf", userid);
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
			System.out.println(accessToken3.accessToken.length());
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
		protected boolean verifyAuthorizationToken(String authorizationToken) throws SQLException {
			return true;
		}

		@Override
		protected void invalidateAccessToken(String refreshToken) throws SQLException {
		}

		@Override
		protected boolean associateAccessTokenPair(String accessToken, String refreshToken, String authorizationToken, long accessExpiration,
				long refreshExporation) throws SQLException {
			return true;
		}

		@Override
		protected boolean associateAccessTokenPair(String accessToken, String refreshToken, String userid, String permission, long accessExpiration,
				long refreshExporation) throws SQLException {
			return true;
		}

		@Override
		protected boolean associateAccessTokenPairRefresh(String accessToken, String refreshToken, String oldRefreshToken, long accessExpiration,
				long refreshExporation) throws SQLException {
			return true;
		}

		@Override
		protected void associateAuthorizationToken(String token, String permissions, String userid, long expiration) throws SQLException {
		}

		@Override
		protected long getAccessTokenLifetime() {
			return 0;
		}
		
		@Override
		protected long getRefreshTokenLifetime() {
			return 0;
		}

		@Override
		protected long getAuthorizationTokenLifetime() {
			return 0;
		}

		@Override
		public String getValidAuthorizationToken(String permissions, String userid) throws SQLException {
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
	}
}
