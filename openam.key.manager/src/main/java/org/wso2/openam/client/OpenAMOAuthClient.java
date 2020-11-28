/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.openam.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.openam.client.model.ClientDetails;
import org.wso2.openam.client.model.ClientInfo;
import org.wso2.openam.client.model.IntrospectionClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.recommendationmgt.AccessTokenGenerator;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.bouncycastle.util.encoders.Base64Encoder;
//import org.bouncycastle.util.encoders.Base64Encoder;
import org.apache.axiom.om.util.Base64;
import org.json.JSONException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
//import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class provides the implementation to use "Custom" Authorization Server
 * for managing OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class OpenAMOAuthClient extends AbstractKeyManager {

	private static final Log log = LogFactory.getLog(OpenAMOAuthClient.class);
	// private Intero introspectClient;
	private IntrospectionClient introspectionClient;
	//static Map<String, ClientDetails> clientDetailsMapping; //new HashMap<String, ClientDetails>();
	private static ClientDetailRepo clientDetailRepo;
	static {
		clientDetailRepo = ClientDetailRepo.getInstance();;
	}

	/**
	 * {@code APIManagerComponent} calls this method, passing
	 * KeyManagerConfiguration as a {@code String}.
	 *
	 * @param keyManagerConfiguration
	 *            Configuration as a {@link KeyManagerConfiguration}
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
		this.configuration = keyManagerConfiguration;
	}

	/**
	 * This method will Register an OAuth client in Custom Authorization Server.
	 *
	 * @param oAuthAppRequest
	 *            This object holds all parameters required to register an OAuth
	 *            client.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

		  OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

	        log.debug("Creating a new oAuthApp in Authorization Server");

	        //KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
	        String registrationEndpoint =  (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT)
	                + "?_action=create";

	        String ssoCookie = getAuthCookieToken();
	        HttpPost httpPut = new HttpPost(registrationEndpoint.trim());
	        HttpClient httpClient = getHttpClient();

	        BufferedReader reader = null;
	        try {
	            final String clientName = oAuthApplicationInfo.getClientName();
	            final String keyType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.KEY_TYPE);
	            //final String clientType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.CLIENT_TYPE);
	            final String clientId = clientName+"_"+keyType;
	            final String scopes =  (String) configuration.getParameter(OpenAMClientConstants.SCOPES);
	            final String grantType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.GRANT_TYPE);
	            final String callbackURL = oAuthApplicationInfo.getCallBackURL();
	            final String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
	            String tokenScopes[] = new String[1];
	            tokenScopes[0] = tokenScope;

	            final String salt = generateSaltValue();

	            log.debug("The generated clientId value is clientId value is: " + clientId);

	            final String clientSecret = generateHmacSHA256Signature(salt, clientId);

	            final String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, this.configuration,
	                    clientSecret);

	            log.debug("Payload for creating new client : " + jsonPayload);

	            httpPut.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
	            httpPut.setHeader(OpenAMClientConstants.CONTENT_TYPE, OpenAMClientConstants.APPLICATION_JSON_CONTENT_TYPE);
	            httpPut.setEntity(new StringEntity(jsonPayload, OpenAMClientConstants.UTF_8));

	            HttpResponse response = httpClient.execute(httpPut);
	            int responseCode = response.getStatusLine().getStatusCode();

	            HttpEntity entity = response.getEntity();
	            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

	            log.debug("response creating new client : " + responseCode);
	            log.debug("response creating new client : " + response);

	            // If successful a 201 will be returned.
	            if (HttpStatus.SC_CREATED == responseCode) {
	                ClientDetails clientDetails = new ClientDetails();
	                oAuthApplicationInfo = new OAuthApplicationInfo();
	                oAuthApplicationInfo.setClientId(clientId);
	                clientDetails.setClientId(clientId);
	                clientDetails.setClientName(clientName);
	                oAuthApplicationInfo.setClientSecret(clientSecret);
	                clientDetails.setClientSecret(clientSecret);
	                oAuthApplicationInfo.addParameter("tokenScope", tokenScopes[0]);
	                clientDetails.setGrantType(grantType);
	                oAuthApplicationInfo.addParameter(OpenAMClientConstants.GRANT_TYPE, grantType);
	                clientDetails.setGrantType(grantType);
	                oAuthApplicationInfo.setCallBackURL(callbackURL);
	                clientDetails.setRedirectURL(callbackURL);
	                //clientDetailsMapping.put(clientId, clientDetails);
	                clientDetailRepo.createApplication(clientId, jsonPayload);
	                return oAuthApplicationInfo;
	            } else {
	                handleException("Some thing wrong here while registering the new client "
	                        + "HTTP Error response code is " + responseCode);
	            }

	        } catch (UnsupportedEncodingException e) {
	            handleException("Encoding for the Response not-supported.", e);
	        } catch (IOException e) {
	            handleException("Error while reading response body ", e);
	        } catch (GeneralSecurityException e) {
	            handleException("Error while creating consumer secret ", e);
	        } finally {
	            // close buffer reader.
	            if (reader != null) {
	                IOUtils.closeQuietly(reader);
	            }
	            httpClient.getConnectionManager().shutdown();
	        }
	        return null;
	}

	/**
	 * This method will update an existing OAuth client in Custom Authorization
	 * Server.
	 *
	 * @param oAuthAppRequest
	 *            Parameters to be passed to Authorization Server, encapsulated as
	 *            an {@code OAuthAppRequest}
	 * @return Details of updated OAuth Client.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

		// todo update oauth app in the authorization server

		return null;
	}

	@Override
	public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
			throws APIManagementException {

		return null;
	}

	/**
	 * Deletes OAuth Client from Authorization Server.
	 *
	 * @param clientId
	 *            consumer key of the OAuth Client.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public void deleteApplication(String clientId) throws APIManagementException {

		 String configURL = (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
	        HttpClient client = getHttpClient();

	        try {
	            configURL += clientId;
	            HttpDelete httpDelete = new HttpDelete(configURL);

	            String ssoCookie = getAuthCookieToken();
	            httpDelete.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
	            HttpResponse response = client.execute(httpDelete);
	            int responseCode = response.getStatusLine().getStatusCode();
	            if (log.isDebugEnabled()) {
	                log.debug("Delete application response code :  " + responseCode);
	            }
	            if (responseCode == HttpStatus.SC_OK ||
	                    responseCode == HttpStatus.SC_NO_CONTENT) {
	            	clientDetailRepo.deleteApplication(clientId);
	                //clientDetailsMapping.remove(clientId);
	                log.info("OAuth Client for consumer Id " + clientId + " has been successfully deleted");
	                //clientDetailsMapping.remove(clientId);
	            } else {
	            	log.error("Problem occurred while deleting client for Consumer Key." +clientId);
	                //handleException("Problem occurred while deleting client for Consumer Key " + clientId);
	            }
	        } catch (IOException e) {
	            handleException("Error while reading response body from Server ", e);
	        } finally {
	            client.getConnectionManager().shutdown();
	        }

	}

	/**
	 * This method retrieves OAuth application details by given consumer key.
	 *
	 * @param clientId
	 *            consumer key of the OAuth Client.
	 * @return an {@code OAuthApplicationInfo} having all the details of an OAuth
	 *         Client.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {

		 OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
	        try {
	            ClientDetails clientDetails = clientDetailRepo.getClientApplication(clientId);

	            if (clientDetails == null || clientDetails.getClientId() == null) {
	                return null;
	            }
	            oAuthApplicationInfo.setClientName(clientDetails.getClientName());
	            oAuthApplicationInfo.setClientId(clientDetails.getClientId());
	            oAuthApplicationInfo.setCallBackURL(clientDetails.getRedirectURL());
	            oAuthApplicationInfo.setClientSecret(clientDetails.getClientSecret());
	            oAuthApplicationInfo.addParameter(OpenAMClientConstants.GRANT_TYPE, clientDetails.getGrantType());

	        } catch (Exception e) {
	            handleException("Something went wrong while retrieving client for consumer key  " + clientId, e);
	        }
	        return oAuthApplicationInfo;
	}

	/**
	 * Gets new access token and returns it in an AccessTokenInfo object.
	 *
	 * @param accessTokenRequest
	 *            Info of the token needed.
	 * @return AccessTokenInfo Info of the new token.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */

	@Override
	public org.wso2.carbon.apimgt.api.model.AccessTokenInfo getNewApplicationAccessToken(
			AccessTokenRequest tokenRequest) throws APIManagementException {
		org.wso2.carbon.apimgt.api.model.AccessTokenInfo accessTokenInfo = new org.wso2.carbon.apimgt.api.model.AccessTokenInfo();
		String newAccessToken;
		long validityPeriod;
		HttpClient client = getHttpClient();
        String configURL = (String)configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        //KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        if (tokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        String applicationTokenScope = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService()
                .getAPIManagerConfiguration().getFirstProperty(APIConstants.APPLICATION_TOKEN_SCOPE);

        // When validity time set to a negative value, a token is considered
        // never to expire.
        if (tokenRequest.getValidityPeriod() == OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            // Setting a different -ve value if the set value is -1 (-1 will be
            // ignored by TokenValidator)
            tokenRequest.setValidityPeriod(-2);
        }

        // Generate New Access Token
        HttpPost httpTokpost = new HttpPost(configURL);
        List<NameValuePair> tokParams = new ArrayList<NameValuePair>(5);
        tokParams.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, OpenAMClientConstants.DEFAULT_GRANT_TYPE_VALUE));
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.OAUTH_RESPONSE_EXPIRY_TIME,
                Long.toString(tokenRequest.getValidityPeriod())));
        String introspectionConsumerKey = (String)configuration.getParameter(OpenAMClientConstants.INTROSPECTION_CK);
        String introspectionConsumerSecret = (String)configuration.getParameter(OpenAMClientConstants.INTROSPECTION_CS);
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.CONSUMER_KEY, introspectionConsumerKey));
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.CONSUMER_SECRET, introspectionConsumerSecret));
        StringBuilder builder = new StringBuilder();
        builder.append(applicationTokenScope);

		for (String scope : tokenRequest.getScope()) {
			if (scope != null && !scope.isEmpty()) {
				builder.append(' ').append(scope);
			}else {
				builder.append(' ').append("default");
			}
		}

        tokParams.add(new BasicNameValuePair("scope", builder.toString()));
        String clientId = tokenRequest.getClientId();
        String clientSecret = tokenRequest.getClientSecret();
        String encodedSecret = Base64
                .encode(new String(clientId + ":" + clientSecret).getBytes());
        try {
            httpTokpost.setHeader("Authorization", "Basic " + encodedSecret);
            httpTokpost.setEntity(new UrlEncodedFormEntity(tokParams, "UTF-8"));
            HttpResponse tokResponse = client.execute(httpTokpost);
            HttpEntity tokEntity = tokResponse.getEntity();
            int responseCode = tokResponse.getStatusLine().getStatusCode();
            if (responseCode != HttpStatus.SC_OK) {
                throw new RuntimeException("Error occurred while calling token endpoint: HTTP error code : "
                        + tokResponse.getStatusLine().getStatusCode());
            } else {
                //tokenInfo = new AccessTokenInfo();
                String responseStr = EntityUtils.toString(tokEntity);
                org.json.JSONObject obj = new org.json.JSONObject(responseStr);
                newAccessToken = obj.get(OpenAMClientConstants.OAUTH_RESPONSE_ACCESSTOKEN).toString();
                validityPeriod = Long.parseLong(obj.get(OpenAMClientConstants.OAUTH_RESPONSE_EXPIRY_TIME).toString());
                if (obj.has("scope")) {
                	accessTokenInfo.setScope(((String) obj.get("scope")).split(" "));
                }
                accessTokenInfo.setAccessToken(newAccessToken);
                accessTokenInfo.setValidityPeriod(validityPeriod);
            }
        } catch (ClientProtocolException exp) {
            handleException("Error while creating token - Invalid protocol used", exp);
        } catch (UnsupportedEncodingException e) {
            handleException("Error while preparing request for token/revoke APIs", e);
        } catch (IOException e) {
            handleException("Error while creating tokens - " + e.getMessage(), e);
        } catch (JSONException e) {
            handleException("Error while parsing response from token api", e);
        }

        return accessTokenInfo;
	}

	/**
	 * This is used to build accesstoken request from OAuth application info.
	 *
	 * @param oAuthApplication
	 *            OAuth application details.
	 * @param tokenRequest
	 *            AccessTokenRequest that is need to be updated with addtional info.
	 * @return AccessTokenRequest after adding OAuth application details.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
			AccessTokenRequest tokenRequest) throws APIManagementException {

		log.debug("Invoking buildAccessTokenRequestFromOAuthApp() method..");
		tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());
        //KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        final String scopes = (String)this.configuration.getParameter("Scope");
        String[] scopeArr = {scopes};
        tokenRequest.setScope(scopeArr);
        return tokenRequest;
	}

	/**
	 * This is used to get the meta data of the accesstoken.
	 *
	 * @param accessToken
	 *            AccessToken.
	 * @return The meta data details of accesstoken.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

		if (log.isDebugEnabled()) {
			log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
					accessToken));
		}
		AccessTokenInfo tokenInfo = new AccessTokenInfo();
        //KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String introspectionURL = (String)configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
        BufferedReader reader = null;

        try {
            String ssoCookie = getAuthCookieToken();
            introspectionURL += accessToken;
            URIBuilder uriBuilder = new URIBuilder(introspectionURL);

            uriBuilder.build();

            HttpGet httpGet = new HttpGet(uriBuilder.build());
            httpGet.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
            HttpClient client = new DefaultHttpClient();


            HttpResponse response = client.execute(httpGet);
            int responseCode = response.getStatusLine().getStatusCode();

            log.info(responseCode);

            if (log.isDebugEnabled()) {
                log.debug("HTTP Response code : " + responseCode);
            }

            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

            if (HttpStatus.SC_OK == responseCode) {
                // pass bufferReader object and get read it and retrieve the
                // parsedJson object
                parsedObject = getParsedObjectByReader(reader);
                log.info("parsedObject"+parsedObject);
                if (parsedObject != null) {

                    Map valueMap = parsedObject;
                    //Object principal = valueMap.get("principal");
                    JSONArray clientIDArray = (JSONArray) valueMap.get(OpenAMClientConstants.CLIENT_ID);
                    if (clientIDArray == null) {
                        tokenInfo.setTokenValid(false);
                        return tokenInfo;
                    }
                    String clientId = (String) clientIDArray.get(0);
                    JSONArray expTimeArray = (JSONArray) valueMap.get("expireTime");
                    Long expiryTimeString = Long.valueOf((String)expTimeArray.get(0));


                    if (expiryTimeString == null) {
                        tokenInfo.setTokenValid(false);
                        //tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
                        return tokenInfo;
                    }

                    long currentTime = System.currentTimeMillis();
                    long expiryTime = expiryTimeString;

                    if (expiryTime > currentTime) {
                        tokenInfo.setTokenValid(true);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setValidityPeriod(expiryTime - currentTime);
                        // Considering Current Time as the issued time.
                        tokenInfo.setIssuedTime(currentTime);
                        JSONArray scopesArray = (JSONArray) valueMap.get("scope");

                        if (scopesArray != null && !scopesArray.isEmpty()) {

                            String[] scopes = new String[scopesArray.size()];
                            for (int i = 0; i < scopes.length; i++) {
                                scopes[i] = (String) scopesArray.get(i);
                            }
                            tokenInfo.setScope(scopes);
                        }
                    } else {
                        tokenInfo.setTokenValid(false);
                        log.info("Invalid Token " + accessToken);
                        //tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }

                } else {
                    log.info("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    //tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            } // for other HTTP error codes we just pass generic message.
            else {
                log.info("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                //tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }

        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException(
                    "HTTP request error has occurred while sending request  to OAuth Provider. " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            handleException("Error occurred while building URL with params." + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
        return tokenInfo;
	}

	@Override
	public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {

		return configuration;
	}

	@Override
	public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {

		return null;
	}

	/**
	 * This method will be called when mapping existing OAuth Clients with
	 * Application in API Manager
	 *
	 * @param oAuthAppRequest
	 *            Details of the OAuth Client to be mapped.
	 * @return {@code OAuthApplicationInfo} with the details of the mapped client.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	@Override
	public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

		return oAuthAppRequest.getOAuthApplicationInfo();
	}

	@Override
	public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {

		// invoke APIResource registration endpoint of the authorization server and
		// creates a new resource.

		return true;
	}

	@Override
	public Map getResourceByApiId(String apiId) throws APIManagementException {

		// retrieves the registered resource by the given API ID from the APIResource
		// registration endpoint.

		return null;
	}

	@Override
	public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {

		return true;
	}

	@Override
	public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
	}

	@Override
	public void deleteMappedApplication(String clientId) throws APIManagementException {
	}

	@Override
	public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {

		return Collections.emptySet();
	}

	@Override
	public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {

		return null;
	}

	@Override
	public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {

		return null;
	}

	@Override
	public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString) throws APIManagementException {

		Map<String, Set<Scope>> apiToScopeMapping = new HashMap<>();
		ApiMgtDAO apiMgtDAO = ApiMgtDAO.getInstance();
		Map<String, Set<String>> apiToScopeKeyMapping = apiMgtDAO.getScopesForAPIS(apiIdsString);
		for (String apiId : apiToScopeKeyMapping.keySet()) {
			Set<Scope> apiScopes = new LinkedHashSet<>();
			Set<String> scopeKeys = apiToScopeKeyMapping.get(apiId);
			for (String scopeKey : scopeKeys) {
				Scope scope = getScopeByName(scopeKey);
				apiScopes.add(scope);
			}
			apiToScopeMapping.put(apiId, apiScopes);
		}
		return apiToScopeMapping;
	}

	@Override
	public void registerScope(Scope scope) throws APIManagementException {

	}

	@Override
	public Scope getScopeByName(String name) throws APIManagementException {

		return null;
	}

	@Override
	public Map<String, Scope> getAllScopes() throws APIManagementException {

		return null;
	}

	@Override
	public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

	}

	@Override
	public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
			Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates) throws APIManagementException {

	}

	@Override
	public void detachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

	}

	@Override
	public void deleteScope(String scopeName) throws APIManagementException {

	}

	@Override
	public void updateScope(Scope scope) throws APIManagementException {

	}

	@Override
	public boolean isScopeExists(String scopeName) throws APIManagementException {

		return false;
	}

	@Override
	public void validateScopes(Set<Scope> scopes) throws APIManagementException {

	}

	@Override
	public String getType() {

		return OpenAMClientConstants.CUSTOM_TYPE;
	}

	/**
	 * Returns a space separate string from list of the contents in the string
	 * array.
	 *
	 * @param stringArray
	 *            an array of strings.
	 * @return space separated string.
	 */
	private static String convertToString(String[] stringArray) {

		if (stringArray != null) {
			StringBuilder sb = new StringBuilder();
			List<String> strList = Arrays.asList(stringArray);
			for (String s : strList) {
				sb.append(s);
				sb.append(" ");
			}
			return sb.toString().trim();
		}

		return null;
	}

//	/**
//	 * Gets an access token.
//	 *
//	 * @param clientId
//	 *            clientId of the oauth client.
//	 * @param clientSecret
//	 *            clientSecret of the oauth client.
//	 * @param parameters
//	 *            list of request parameters.
//	 * @return an {@code JSONObject}
//	 * @throws APIManagementException
//	 *             This is the custom exception class for API management.
//	 */
//	private AccessTokenInfo getAccessToken(String clientId, String clientSecret, List<NameValuePair> parameters)
//			throws APIManagementException {
//
//		try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
//			String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
//			HttpPost httpPost = new HttpPost(tokenEndpoint);
//			httpPost.setEntity(new UrlEncodedFormEntity(parameters));
//			String encodedCredentials = getEncodedCredentials(clientId, clientSecret);
//
//			httpPost.setHeader(OpenAMConstants.AUTHORIZATION,
//					OpenAMConstants.AUTHENTICATION_BASIC + encodedCredentials);
//			if (log.isDebugEnabled()) {
//				log.debug("Invoking HTTP request to get the accesstoken.");
//			}
//			HttpResponse response = httpClient.execute(httpPost);
//			int statusCode = response.getStatusLine().getStatusCode();
//			HttpEntity entity = response.getEntity();
//			if (entity == null) {
//				handleException(String.format(OpenAMConstants.STRING_FORMAT,
//						OpenAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
//			}
//			if (org.apache.commons.httpclient.HttpStatus.SC_OK == statusCode) {
//
//				try (InputStream inputStream = entity.getContent()) {
//					String content = IOUtils.toString(inputStream);
//					return new Gson().fromJson(content, AccessTokenInfo.class);
//
//				}
//			}
//		} catch (UnsupportedEncodingException e) {
//			handleException(OpenAMConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
//		} catch (IOException e) {
//			handleException(OpenAMConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
//		}
//		return null;
//	}

//	/**
//	 * Returns base64 encoded credentaials.
//	 *
//	 * @param clientId
//	 *            clientId of the oauth client.
//	 * @param clientSecret
//	 *            clientSecret of the oauth clients.
//	 * @return String base64 encode string.
//	 */
//	private static String getEncodedCredentials(String clientId, String clientSecret) throws APIManagementException {
//
//		String encodedCredentials;
//		try {
//			encodedCredentials = Base64.getEncoder()
//					.encodeToString((clientId + ":" + clientSecret).getBytes(OpenAMConstants.UTF_8));
//		} catch (UnsupportedEncodingException e) {
//			throw new APIManagementException(OpenAMConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
//		}
//
//		return encodedCredentials;
//	}

	/**
	 * Common method to throw exceptions. This will only expect one parameter.
	 *
	 * @param msg
	 *            error message as a string.
	 * @throws APIManagementException
	 *             This is the custom exception class for API management.
	 */
	private static void handleException(String msg) throws APIManagementException {

		log.error(msg);
		throw new APIManagementException(msg);
	}
	
	private String getAuthCookieToken() throws APIManagementException{

        //KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        String registrationEndpoint = (String) configuration.getParameter(OpenAMClientConstants.OPENAM_AUTH_ENDPOINT);
        HttpPost httpPut = new HttpPost(registrationEndpoint.trim());
        HttpClient httpClient = getHttpClient();

        BufferedReader reader = null;
        try {
            // Create the JSON Payload that should be sent to OAuth Server.

            httpPut.setHeader(OpenAMClientConstants.CONTENT_TYPE, OpenAMClientConstants.APPLICATION_JSON_CONTENT_TYPE);
            String introspectionConsumerKey = (String) configuration.getParameter(OpenAMClientConstants.INTROSPECTION_CK);
            String introspectionConsumerSecret = (String) configuration.getParameter(OpenAMClientConstants.INTROSPECTION_CS);
            httpPut.setHeader(OpenAMClientConstants.X_OPENAM_USERNAME, introspectionConsumerKey);
            httpPut.setHeader(OpenAMClientConstants.X_OPENAM_PASSWORD, introspectionConsumerSecret);
            HttpResponse response = httpClient.execute(httpPut);
            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

            // If successful a 201 will be returned.
            if (HttpStatus.SC_OK == responseCode) {
                String responseStr = EntityUtils.toString(entity);
                org.json.JSONObject obj = new org.json.JSONObject(responseStr);
                String cookieToken = obj.get(OpenAMClientConstants.TOKEN_ID).toString();

                return cookieToken;

            } else {
                handleException("Some thing wrong here while registering the new client "
                        + "HTTP Error response code is " + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } catch (JSONException e) {
            handleException("Error while reading response body ", e);
        }  finally {
            // close buffer reader.
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }
	
	/**
    *
    * /** This method will return HttpClient object.
    *
    * @return HttpClient object.
    */
   private HttpClient getHttpClient() {
       HttpClient httpClient = new DefaultHttpClient();
       return httpClient;
   }
   
//   private static String generateSaltValue() throws NoSuchAlgorithmException {
//       byte[] bytes = new byte[16];
//       SecureRandom secureRandom = SecureRandom.getInstance(OpenAMClientConstants.RANDOM_ALG_SHA1);
//       secureRandom.nextBytes(bytes);
//       return Base64.getEncoder().encodeToString(bytes);
//   }
   
   private static String generateSaltValue() throws NoSuchAlgorithmException {
       byte[] bytes = new byte[16];
       SecureRandom secureRandom = SecureRandom.getInstance(OpenAMClientConstants.RANDOM_ALG_SHA1);
       secureRandom.nextBytes(bytes);
       return Base64.encode(bytes);
   }
   
   private static String generateHmacSHA256Signature(final String data, final String key)
           throws GeneralSecurityException, IOException {
       byte[] hmacData = null;
       try {
           final SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
           final Mac mac = Mac.getInstance("HmacSHA256");
           mac.init(secretKey);
           hmacData = mac.doFinal(data.getBytes("UTF-8"));
           final ByteArrayOutputStream os = new ByteArrayOutputStream();
           final Base64Encoder encoder = new Base64Encoder();
           encoder.encode(hmacData, 0, hmacData.length, (OutputStream) os);
           return os.toString();
       } catch (UnsupportedEncodingException e) {
           throw new GeneralSecurityException(e);
       }
   }
   
   /**
    * This method can be used to create a JSON Payload out of the Parameters
    * defined in an OAuth Application.
    *
    * @param oAuthApplicationInfo
    *            Object that needs to be converted.
    * @return
    */
   private String createJsonPayloadFromOauthApplication(final OAuthApplicationInfo oAuthApplicationInfo,
                                                        final KeyManagerConfiguration config, final String secret) {
       final Map<String, Object> paramMap = new HashMap<String, Object>();
       final String keyType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.KEY_TYPE);
       final String clientName = oAuthApplicationInfo.getClientName();
       final String clientId = clientName+"_"+keyType;
       final JSONArray clientids = new JSONArray();
       JSONObject parsedObject;
 
		String additionalProperties = (String) oAuthApplicationInfo.getParameter("additionalProperties");
		JSONParser parser = new JSONParser();
		if (additionalProperties != null) {
			try {
				parsedObject = (JSONObject) parser.parse(additionalProperties);
				final JSONArray clientType = new JSONArray();
			    clientType.add((String) parsedObject.get(OpenAMClientConstants.CLIENT_TYPE));
			    paramMap.put(OpenAMClientConstants.CLIENT_TYPE_IM, clientType);
			    
			    final JSONArray scopes = new JSONArray();
			    scopes.add("default");
			    scopes.add("am_application_scope");
			    paramMap.put(OpenAMClientConstants.SCOPES_IM, scopes);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}


       clientids.add(clientId);
       paramMap.put("client_id", clientids);

       final JSONArray realm = new JSONArray();
       realm.add(config.getParameter("Realm"));
       paramMap.put("realm", realm);

       final JSONArray userpassword = new JSONArray();
       userpassword.add(secret);
       paramMap.put("userpassword", userpassword);

       final JSONArray redirectionuri = new JSONArray();
       redirectionuri.add(oAuthApplicationInfo.getCallBackURL());
       paramMap.put(OpenAMClientConstants.REDIRECT_URL_IM, redirectionuri);

       final JSONArray responseType = new JSONArray();
       responseType.add("code");
       responseType.add("token");
       responseType.add("id_token");
       responseType.add("code token");
       responseType.add("token id_token");
       responseType.add("code id_token");
       responseType.add("code token id_token");
       paramMap.put(OpenAMClientConstants.RESPONSE_TYPE_IM, responseType);


       final JSONArray clientNameArr = new JSONArray();
       clientNameArr.add(clientName);
       paramMap.put(OpenAMClientConstants.CLIENT_NAME_IM, clientNameArr);

       log.debug("request" + JSONObject.toJSONString((Map) paramMap));
       return JSONObject.toJSONString((Map) paramMap);
   }
   
   /**
    * Can be used to parse {@code BufferedReader} object that are taken from
    * response stream, to a {@code JSONObject}.
    *
    * @param reader
    *            {@code BufferedReader} object from response.
    * @return JSON payload as a name value map.
    */
   private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

       JSONObject parsedObject = null;
       JSONParser parser = new JSONParser();
       if (reader != null) {
           parsedObject = (JSONObject) parser.parse(reader);

       }
       return parsedObject;
   }


}
