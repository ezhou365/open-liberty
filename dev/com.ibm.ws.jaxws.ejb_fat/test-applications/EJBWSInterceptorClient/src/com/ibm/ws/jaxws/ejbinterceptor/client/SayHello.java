//
// Generated By:JAX-WS RI IBM 2.2.1-11/28/2011 08:28 AM(foreman)- (JAXB RI IBM 2.2.3-11/28/2011 06:21 AM(foreman)-)
//

package com.ibm.ws.jaxws.ejbinterceptor.client;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

@WebService(name = "SayHello", targetNamespace = "http://ejbinterceptor.jaxws.ws.ibm.com/")
@XmlSeeAlso({
             ObjectFactory.class
})
public interface SayHello {

    /**
     * 
     * @param arg0
     * @return
     *         returns java.lang.String
     */
    @WebMethod
    @WebResult(targetNamespace = "")
    @RequestWrapper(localName = "hello", targetNamespace = "http://ejbinterceptor.jaxws.ws.ibm.com/", className = "com.ibm.ws.jaxws.ejbinterceptor.client.Hello")
    @ResponseWrapper(localName = "helloResponse", targetNamespace = "http://ejbinterceptor.jaxws.ws.ibm.com/", className = "com.ibm.ws.jaxws.ejbinterceptor.client.HelloResponse")
    public String hello(
                        @WebParam(name = "arg0", targetNamespace = "") String arg0);

}