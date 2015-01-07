package net.jforum.sso;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.Cookie;

import net.jforum.ControllerUtils;
import net.jforum.context.RequestContext;
import net.jforum.entities.UserSession;
import net.jforum.util.preferences.ConfigKeys;
import net.jforum.util.preferences.SystemGlobals;

import org.apache.log4j.Logger;

public class CookieUserSSO implements SSO {
	static final Logger logger = Logger.getLogger(CookieUserSSO.class.getName());
	String userName;
	String userID;
	String email;
	public final String COOKIE_NAME = "jforumUserId";

	public String authenticateUser(RequestContext request) {
		Cookie cookieNameUser = ControllerUtils.getCookie("jforumSSOCookieNameUser");
		String username = null;

		if (cookieNameUser != null) {
			try {
				username = java.net.URLDecoder.decode(cookieNameUser.getValue(), "utf-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return username;

	}

	public boolean isSessionValid(UserSession userSession, RequestContext request) {
		Cookie cookieNameUser = ControllerUtils.getCookie(SystemGlobals.getValue(ConfigKeys.COOKIE_NAME_USER));
		String remoteUser = null;

		if (cookieNameUser != null) {
			remoteUser = cookieNameUser.getValue();
		}

		if (remoteUser == null && userSession.getUserId() != SystemGlobals.getIntValue(ConfigKeys.ANONYMOUS_USER_ID)) {
			return false;
		} else if (remoteUser != null && userSession.getUserId() == SystemGlobals.getIntValue(ConfigKeys.ANONYMOUS_USER_ID)) {
			return false;
		} else if (remoteUser != null && !remoteUser.equals(userSession.getUsername())) {
			return false;
		}
		return true;
	}

}
