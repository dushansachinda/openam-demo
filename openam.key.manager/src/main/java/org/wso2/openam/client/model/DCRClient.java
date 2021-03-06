/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.openam.client.model;

import feign.Headers;
import feign.Param;
import feign.RequestLine;

/**
 * DCR client to Create Oauth application
 */
public interface DCRClient {

    @RequestLine("POST")
    @Headers("Content-Type: application/json")
    public ClientInfo createApplication(ClientInfo clientInfo);

    @RequestLine("GET /{clientId}")
    @Headers("Content-Type: application/json")
    public ClientInfo getApplication(@Param("clientId") String clientId);

    @RequestLine("PUT /{clientId}")
    @Headers("Content-Type: application/json")
    public ClientInfo updateApplication(@Param("clientId") String clientId, ClientInfo clientInfo);

    @RequestLine("DELETE /{clientId}")
    @Headers("Content-Type: application/json")
    public void deleteApplication(@Param("clientId") String clientId);

}
