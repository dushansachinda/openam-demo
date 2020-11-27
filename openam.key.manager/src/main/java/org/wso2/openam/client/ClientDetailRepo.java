package org.wso2.openam.client;

import java.util.HashMap;
import java.util.Map;

import org.wso2.openam.client.model.ClientDetails;

public class ClientDetailRepo {
	public Map<String, ClientDetails> clientDetailsMapping = new HashMap<String, ClientDetails>();

	static ClientDetailRepo clientDetailRepo;

	public static ClientDetailRepo getInstance() {
		if (clientDetailRepo == null) {
			clientDetailRepo = new ClientDetailRepo();
		}
		return clientDetailRepo;
	}

}
