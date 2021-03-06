/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.openam.client.model;

import com.google.gson.annotations.SerializedName;

/**
 * Access token generated information
 */
public class AccessTokenInfo {

    @SerializedName("access_token")
    private String accessToken;
    @SerializedName("token_type")
    private String tokenType;
    @SerializedName("expires_in")
    private long expiry;
    @SerializedName("refresh_expires_in")
    private long refreshTokenExpiry;

    @SerializedName("refresh_token")
    private String refreshToken;

    @SerializedName("not-before-policy")
    private long notBeforePolicy;
    @SerializedName("session_state")
    private String sessionState;
    @SerializedName("scope")
    private String scope;

    public String getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public long getExpiry() {

        return expiry;
    }

    public void setExpiry(long expiry) {

        this.expiry = expiry;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public long getRefreshTokenExpiry() {

        return refreshTokenExpiry;
    }

    public void setRefreshTokenExpiry(long refreshTokenExpiry) {

        this.refreshTokenExpiry = refreshTokenExpiry;
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {

        this.refreshToken = refreshToken;
    }

    public long getNotBeforePolicy() {

        return notBeforePolicy;
    }

    public void setNotBeforePolicy(long notBeforePolicy) {

        this.notBeforePolicy = notBeforePolicy;
    }

    public String getSessionState() {

        return sessionState;
    }

    public void setSessionState(String sessionState) {

        this.sessionState = sessionState;
    }
}
