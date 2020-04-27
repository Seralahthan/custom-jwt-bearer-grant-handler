package org.wso2.carbon.apimgt.keymgt.token.custom.jwt.handler;

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import net.minidev.json.JSONArray;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.jwt.JWTBearerGrantHandler;
import org.wso2.carbon.identity.oauth2.grant.jwt.JWTConstants;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.text.ParseException;
import java.util.ArrayList;

public class CustomJWTBearerGrantHandler extends JWTBearerGrantHandler {
    private static Log log = LogFactory.getLog(CustomJWTBearerGrantHandler.class);

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        SignedJWT signedJWT = null;
        JSONArray userScopes = null;

        if(log.isDebugEnabled()) {
            log.debug("Entering the CustomJWTBearerGrantHandler");
        }

        try {
            signedJWT = getSignedJWT(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            log.error("Couldn't retrieve signed JWT", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Extracting the Json payload from the signed JWT");
        }

        //Extracting the JSON payload
        JSONObject jsonPayload = signedJWT != null ? signedJWT.getPayload().toJSONObject() : null;

        //Look in the JWT token for "scope" and "scopes" as claims
        if (jsonPayload != null) {
            if (jsonPayload.containsKey("scope") && jsonPayload.containsKey("scopes")) {
                userScopes = formatScopes(jsonPayload, "scopes");
            } else if (jsonPayload.containsKey("scope")) {
                userScopes = formatScopes(jsonPayload, "scope");
            } else if (jsonPayload.containsKey("scopes")){
                userScopes = formatScopes(jsonPayload, "scopes");
            }
        }

        if (userScopes != null) {
            String[] requestedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
            if (requestedScopes != null) {
                tokReqMsgCtx.setScope(filterScopes(userScopes, requestedScopes));
            }
        }

        return super.validateScope(tokReqMsgCtx);
    }

    //Formats the "scope" Or "scopes" claim to only allow a String Or a JSONArray
    private JSONArray formatScopes(JSONObject jsonPayload, String key) {
        JSONArray userScopesArr = null;

        if (jsonPayload.get(key) instanceof String) {
            userScopesArr = new JSONArray();
            userScopesArr.add(jsonPayload.get(key));
            return userScopesArr;
        }

        if (jsonPayload.get(key) instanceof JSONArray) {
            userScopesArr = (JSONArray) jsonPayload.get(key);
        }

        return userScopesArr;
    }

    private String[] filterScopes(JSONArray userScopes, String[] requestedScopes) {
        ArrayList<String> filteredScopes = new ArrayList<String>();
        for (String requestedScope:requestedScopes) {
            if (userScopes.toString().contains(requestedScope)){
                filteredScopes.add(requestedScope);
            }
        }

        return filteredScopes.toArray(new String[filteredScopes.size()]);
    }

    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT = null;
        for (RequestParameter param : params) {
            if (param.getKey().equals(JWTConstants.OAUTH_JWT_ASSERTION)) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(assertion)) {
            String errorMessage = "Error while retrieving the assertion";
            throw new IdentityOAuth2Exception(errorMessage);
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            if (log.isDebugEnabled()) {
                log.debug(signedJWT);
            }
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the JWT";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return signedJWT;
    }
}
