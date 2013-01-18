package hemera.ext.oauth.request.flow;

import java.util.Map;

/**
 * <code>FlowAccessCredentialsPostRequest</code> defines
 * the request for OAuth resource access token client
 * credentails action post operation.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAccessCredentialsPostRequest extends AbstractFlowAccessRequest {
	/**
	 * The <code>String</code> user name.
	 */
	public String username;
	/**
	 * The <code>String</code> password.
	 */
	public String password;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		super.parse(path, arguments);
		// User name.
		this.username = (String)arguments.get("username");
		if (this.username == null || this.username.trim().isEmpty()) {
			throw new IllegalArgumentException("Username must be specified.");
		}
		this.username = this.username.trim();
		// Password.
		this.password = (String)arguments.get("password");
		if (this.password == null || this.password.trim().isEmpty()) {
			throw new IllegalArgumentException("Password must be specified.");
		}
		this.password = this.password.trim();
	}
}
