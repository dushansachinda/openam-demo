package org.wso2.openam.client;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
import org.wso2.openam.client.model.ClientDetails;

public class ClientDetailRepo {
	public Map<String, ClientDetails> clientDetailsMapping = new HashMap<String, ClientDetails>();

	private static final Log log = LogFactory.getLog(ApiMgtDAO.class);
	static ClientDetailRepo clientDetailRepo;

	public static ClientDetailRepo getInstance() {
		if (clientDetailRepo == null) {
			clientDetailRepo = new ClientDetailRepo();
		}
		return clientDetailRepo;
	}

	public void createApplication(String clientid, String json) throws APIManagementException {
		Connection conn = null;
		PreparedStatement queryPs = null;
		ResultSet resultSet = null;
		try {
			String addquery = OpenAMClientConstants.INSERT_OPENAM_CLIENT;
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);
			queryPs = conn.prepareStatement(addquery);
			queryPs.setString(1, clientid);
			queryPs.setString(2, json);
			queryPs.execute();
			conn.commit();
		} catch (SQLException e) {
			try {
				if (conn != null) {
					conn.rollback();
				}
			} catch (SQLException e1) {
				handleException("Error occurred while Rolling back changes done on Application Registration", e1);
			}
			handleException("Error occurred while creating an " + "Application  Entry for Application : " + clientid,
					e);
		} finally {
			APIMgtDBUtil.closeStatement(queryPs);
			APIMgtDBUtil.closeAllConnections(queryPs, conn, resultSet);
		}
	}

	public void deleteApplication(String clientid) throws APIManagementException {
		Connection conn = null;
		PreparedStatement queryPs = null;
		ResultSet resultSet = null;
		try {
			String addquery = OpenAMClientConstants.DELETE_OPENAM_CLIENT;
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);
			queryPs = conn.prepareStatement(addquery);
			queryPs.setString(1, clientid);
			queryPs.execute();
			conn.commit();
		} catch (SQLException e) {
			try {
				if (conn != null) {
					conn.rollback();
				}
			} catch (SQLException e1) {
				handleException("Error occurred while delete Application Registration", e1);
			}
			handleException("Error occurred while delete an " + "Application  Entry for Application : " + clientid, e);
		} finally {
			APIMgtDBUtil.closeStatement(queryPs);
			APIMgtDBUtil.closeAllConnections(queryPs, conn, resultSet);
		}

	}

	public ClientDetails getClientApplication(String clientid) throws APIManagementException {
		Connection conn = null;
		PreparedStatement queryPs = null;
		ResultSet resultSet = null;
		String result = "";
		ClientDetails clientDetails = new ClientDetails();
		try {
			String addquery = OpenAMClientConstants.READ_OPENAM_CLIENT;
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);
			queryPs = conn.prepareStatement(addquery);
			queryPs.setString(1, clientid);
			resultSet = queryPs.executeQuery();
			while (resultSet.next()) {
				result = resultSet.getString(1);
			}
		} catch (SQLException e) {
			try {
				if (conn != null) {
					conn.rollback();
				}
			} catch (SQLException e1) {
				handleException("Error occurred while reading openam Application ", e1);
			}
			handleException("Error occurred while reading an " + "Application  Entry for Application : " + clientid, e);
		} finally {
			APIMgtDBUtil.closeStatement(queryPs);
			APIMgtDBUtil.closeAllConnections(queryPs, conn, resultSet);
		}
		generateClientObject(result, clientDetails);
		return clientDetails;
	}

	// {"client_id":["testClient"],
	// "realm":["/"],
	// "userpassword":["secret12"],
	// "com.forgerock.openam.oauth2provider.clientType":["Confidential"],
	// "com.forgerock.openam.oauth2provider.redirectionURIs":
	// ["www.client.com","www.example.com"],
	// "com.forgerock.openam.oauth2provider.scopes":["cn","sn"],
	// "com.forgerock.openam.oauth2provider.defaultScopes":["cn"],
	// "com.forgerock.openam.oauth2provider.name":["My Test Client"],
	// "com.forgerock.openam.oauth2provider.description":["OAuth 2.0 Client"]
	// }
	//
	// {
	// "com.forgerock.openam.oauth2provider.clientType": [null],
	// "com.forgerock.openam.oauth2provider.redirectionURIs": [null],
	// "com.forgerock.openam.oauth2provider.scopes": [null],
	// "com.forgerock.openam.oauth2provider.clientName": ["aaaa"],
	// "com.forgerock.openam.oauth2provider.responseTypes": [
	// "code",
	// "token",
	// "id_token",
	// "code token",
	// "token id_token",
	// "code id_token",
	// "code token id_token"
	// ],
	// "realm": [null],
	// "client_id": ["aaaa_PRODUCTION"],
	// "userpassword": ["SpxLiBQ68LjqI21TEHYt2CwFIx2EcYeHddCFd6vs1QU="]
	// }
	private void generateClientObject(String result, ClientDetails clientDetails) {
		JSONParser parser = new JSONParser();
		JSONObject parsedObject;
		if (result != null) {
			try {
				parsedObject = (JSONObject) parser.parse(result);
				clientDetails.setClientId(methodExtractObj(parsedObject,"client_id"));
				clientDetails.setClientSecret(methodExtractObj(parsedObject,"userpassword"));
				clientDetails.setClientName(methodExtractObj(parsedObject,"com.forgerock.openam.oauth2provider.clientName"));
				clientDetails.setGrantType(methodExtractObjArr(parsedObject,"com.forgerock.openam.oauth2provider.responseTypes"));
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	private String methodExtractObjArr(JSONObject parsedObject, String value) {
		// TODO Auto-generated method stub
		StringBuilder grantTypes = new StringBuilder();
		JSONArray aobj = (JSONArray)parsedObject.get(value);
		for(Object o: aobj){
		    //if ( o instanceof JSONObject ) {
		    	grantTypes.append(o);
		    	grantTypes.append(",");
		    //}
		}
		return grantTypes.toString();
	}

	private String methodExtractObj(JSONObject parsedObject,String value) {
		JSONArray aobj = (JSONArray)parsedObject.get(value);
		String obj = (String)aobj.get(0);
		return obj;
	}

	private void handleException(String msg, Throwable t) throws APIManagementException {
		log.error(msg, t);
		throw new APIManagementException(msg, t);
	}

	public static void main(String ar[]) {
		ClientDetailRepo clientDetailRepo = ClientDetailRepo.getInstance();
		String result = "{\n" + 
				"   \"com.forgerock.openam.oauth2provider.clientType\": [null],\n" + 
				"   \"com.forgerock.openam.oauth2provider.redirectionURIs\": [null],\n" + 
				"   \"com.forgerock.openam.oauth2provider.scopes\": [null],\n" + 
				"   \"com.forgerock.openam.oauth2provider.clientName\": [\"aaaa\"],\n" + 
				"   \"com.forgerock.openam.oauth2provider.responseTypes\": [\n" + 
				"      \"code\",\n" + 
				"      \"token\",\n" + 
				"      \"id_token\",\n" + 
				"      \"code token\",\n" + 
				"      \"token id_token\",\n" + 
				"      \"code id_token\",\n" + 
				"      \"code token id_token\"\n" + 
				"   ],\n" + 
				"   \"realm\": [null],\n" + 
				"   \"client_id\": [\"aaaa_PRODUCTION\"],\n" + 
				"   \"userpassword\": [\"SpxLiBQ68LjqI21TEHYt2CwFIx2EcYeHddCFd6vs1QU=\"]\n" + 
				"}";

		ClientDetails clientDetails = new ClientDetails();
		clientDetailRepo.generateClientObject(result, clientDetails);
		System.out.println("dd");

	}

}
