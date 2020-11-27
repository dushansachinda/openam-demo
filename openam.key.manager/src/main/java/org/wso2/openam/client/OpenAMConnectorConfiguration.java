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

package org.wso2.openam.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component(name = "custom.configuration.component", immediate = true, service = KeyManagerConnectorConfiguration.class)
public class OpenAMConnectorConfiguration implements KeyManagerConnectorConfiguration {

	@Override
	public String getImplementation() {

		return org.wso2.openam.client.OpenAMOAuthClient.class.getName();
	}

	@Override
	public String getJWTValidator() {

		// If you need to implement a custom JWT validation logic you need to implement
		// org.wso2.carbon.apimgt.impl.jwt.JWTValidator interface and instantiate it in
		// here.
		return null;
	}

	/*
	 * Provides list of Configurations that need to show in Admin portal in order to
	 * connect with KeyManager
	 *
	 */
	@Override
	public List<ConfigurationDto> getConnectionConfigurations() {

		List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

		configurationDtoList.add(new ConfigurationDto("client_id", "Client ID", "input",
				"Client ID of open AM service Application (admin password)", "", true, false, Collections.emptyList(),
				false));
		configurationDtoList.add(new ConfigurationDto("client_secret", "Client Secret", "input",
				"Client Secret of service Application (admin username)", "", true, true, Collections.emptyList(),
				false));
//		configurationDtoList
//        .add(new ConfigurationDto("end_point_auth_url", "EndPoint Auth URL ", "input", "EndPoint Auth URL of open AM service Application", "",
//                true,
//                false, Collections.emptyList(), false));
		return configurationDtoList;
	}

	/*
	 * Provides list of configurations need to create Oauth applications in Oauth
	 * server in Devportal
	 *
	 */
	@Override
	public List<ConfigurationDto> getApplicationConfigurations() {

		List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

		// todo add application configuration parameters that need create an OAuth
		// application in the OAuth Server
		configurationDtoList.add(new ConfigurationDto("application_type", "Application Type", "select",
				"Type Of Application to " + "create", "web", false, false,
				Arrays.asList("web", "native", "service", "browser"), false));
		configurationDtoList.add(new ConfigurationDto("response_types", "Response Type", "select",
				"Type Of Token response", "", true, false, Arrays.asList("code", "token", "id_token"), true));
		configurationDtoList
				.add(new ConfigurationDto("token_endpoint_auth_method", "Token endpoint Authentication Method",
						"select", "How to Authenticate Token Endpoint", "client_secret_basic", true, true,
						Arrays.asList("client_secret_basic", "client_secret_post", "client_secret_jwt"), false));
		configurationDtoList
		.add(new ConfigurationDto("client_type", "Client Type",
				"select", "How to the Client Type", "Confidential", true, true,
				Arrays.asList("Confidential", "Public"), false));
		
		return configurationDtoList;
	}

	@Override
	public String getType() {

		return OpenAMClientConstants.CUSTOM_TYPE;
	}

	@Override
	public String getDisplayName() {

		return OpenAMClientConstants.DISPLAY_NAME;
	}
}
