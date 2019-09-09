package com.ibm.ws.security.openidconnect.token;

import org.joda.time.Duration;
import org.joda.time.Instant;
//import net.oauth.jsontoken.SystemClock;

public class FakeClock  {

    private Instant now = new Instant();

    public FakeClock() {
        
    }

    public FakeClock(Duration acceptableClockSkew) {
       
    }

    public void setNow(Instant i) {
        now = i;
    }

    
    public Instant now() {
        return now;
    }
}
