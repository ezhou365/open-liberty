package com.ibm.ws.security.openidconnect.token;

import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.security.openidconnect.token.impl.IdTokenImpl;

public class mockIDToken extends IDToken {

    public mockIDToken(String tokenString, @Sensitive Object key, String clientId, String issuer,
            String signingAlgorithm) {
        super(tokenString, key, clientId, issuer, signingAlgorithm);
    }

    public void startMock(Payload myPayload) {
        this.payload = myPayload;
    }

    @Override
    public void addToPayloadFields(IdTokenImpl idTokenImpl, String key) {
        super.addToPayloadFields(idTokenImpl, key);
    }

    @Override
    public void addToPayloadFields(String key) {
        super.addToPayloadFields(key);
    }
}
