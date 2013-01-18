package hemera.ext.oauth.request.flow;

import java.util.Map;

/**
 * <code>FlowAuthorizePostRequest</code> defines the
 * request for the OAuth resource authorize action
 * post operation.
 * <p>
 * This request is intended to be only created and
 * sent by the authorization server internally.
 *
 * @author Yi Wang (Neakor)
 * @version 1.0.0
 */
public class FlowAuthorizePostRequest extends AbstractFlowRequest {
	/**
	 * The <code>String</code> authorization server
	 * consumer key. If this value is <code>null</code>,
	 * the agent will be redirected to the authorization
	 * server for authentication and consumer permission
	 * authorization.
	 */
	public String authServerKey;
	/**
	 * The <code>String</code> authorization server
	 * consumer secret. If this value is <code>null</code>,
	 * the agent will be redirected to the authorization
	 * server for authentication and consumer permission
	 * authorization.
	 */
	public String authServerSecret;
	/**
	 * The <code>String</code> user ID. If this value
	 * is <code>null</code>, the agent will be redirected
	 * to the authorization server for authentication
	 * and the consumer permission authorization.
	 */
	public String userid;
	/**
	 * The <code>String</code> permissions requested.
	 */
	public String permissions;

	@Override
	public void parse(final String[] path, final Map<String, Object> arguments) throws Exception {
		super.parse(path, arguments);
		// Authorization server consumer key.
		this.authServerKey = (String)arguments.get("auth_server_key");
		// Authorization server consumer secret.
		this.authServerSecret = (String)arguments.get("auth_server_secret");
		// User ID can be null, which will trigger redirect.
		this.userid = (String)arguments.get("user_id");
		// Permissions.
		this.permissions = (String)arguments.get("permissions");
		if (this.permissions == null || this.permissions.trim().isEmpty()) {
			throw new IllegalArgumentException("Permissions must be specified.");
		}
		this.permissions = this.permissions.trim();
	}
}
