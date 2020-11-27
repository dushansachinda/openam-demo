package org.wso2.openam.client.model;


public class ClientDetails {

    private String clientId;
    private String clientSecret;
    private String clientName;
    private String redirectURL;
    private String grantType;

    public String getClientId() {
        return clientId;
    }
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    public String getClientSecret() {
        return clientSecret;
    }
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    public String getRedirectURL() {
        return redirectURL;
    }
    public void setRedirectURL(String redirectURL) {
        this.redirectURL = redirectURL;
    }
    public String getGrantType() {
        return grantType;
    }
    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }


}
