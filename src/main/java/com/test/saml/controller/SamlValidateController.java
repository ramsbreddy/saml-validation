package com.test.saml.controller;


import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.io.IOUtils;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Controller;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.xml.namespace.QName;
import javax.xml.soap.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;

@Controller
@Slf4j
public class SamlValidateController {

    @PostConstruct
    public void validate() {
        try {
            InitializationService.initialize();
            String samlString ="<?xml version=\"1.0\"?>\n" +
                    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"pfxe10bae1d-ad19-f052-fbd4-1c1cd16f5cb5\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">\n" +
                    "  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                    "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                    "  <ds:Reference URI=\"#pfxe10bae1d-ad19-f052-fbd4-1c1cd16f5cb5\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>mO2hMyjrkCcP27WOvfl5QukmWZ8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gIihnkrxpDOLKeSEVsItvYxKtzeNFc83uzkqlfVaq/i0xkr8UtMobAk34h5NI/BC9ILodtYwb2WFf9yscfp3rhMoWWwRqAl1Uwh4zKsTv9hWV6Uwso8ojyPn71n8EHHKuUmdhROiuo20G6Z+VVEFmUr8pImId5mgEAenSa3o9NI=</ds:SignatureValue>\n" +
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                    "  <samlp:Status>\n" +
                    "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                    "  </samlp:Status>\n" +
                    "  <saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"pfx4007d6b8-1c5c-17a4-18d8-3189179412a6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">\n" +
                    "    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                    "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                    "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                    "  <ds:Reference URI=\"#pfx4007d6b8-1c5c-17a4-18d8-3189179412a6\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>xBSWd4x30R1Wa30qa/CPJzwWDqc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>PuHiOJsxu5msG8Bbx+CuW5XkS4UxlMXhRbIWkFCXJEiWdT00nzSpQ31JsN+2jUEzkdGa14A61PKgyWlNLSZRJOEtWuhz0DJxYS9OdYVl+yxHEIX2Hz/FOGde+tVQsS7nq1mX8nO8IgRLE0vmhfQcQHvUHWdIa+ufpWgh0Dg3DN0=</ds:SignatureValue>\n" +
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                    "    <saml:Subject>\n" +
                    "      <saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>\n" +
                    "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                    "        <saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>\n" +
                    "      </saml:SubjectConfirmation>\n" +
                    "    </saml:Subject>\n" +
                    "    <saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">\n" +
                    "      <saml:AudienceRestriction>\n" +
                    "        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>\n" +
                    "      </saml:AudienceRestriction>\n" +
                    "    </saml:Conditions>\n" +
                    "    <saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">\n" +
                    "      <saml:AuthnContext>\n" +
                    "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" +
                    "      </saml:AuthnContext>\n" +
                    "    </saml:AuthnStatement>\n" +
                    "    <saml:AttributeStatement>\n" +
                    "      <saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                    "        <saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>\n" +
                    "      </saml:Attribute>\n" +
                    "      <saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                    "        <saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>\n" +
                    "      </saml:Attribute>\n" +
                    "      <saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                    "        <saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>\n" +
                    "        <saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>\n" +
                    "      </saml:Attribute>\n" +
                    "    </saml:AttributeStatement>\n" +
                    "  </saml:Assertion>\n" +
                    "</samlp:Response>";
            Response response = getSamlAssertion(samlString);

            SignatureValidator.validate(response.getSignature(), getSigningCredential());
            System.out.println("Done");
            parseSoap();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void parseSoap() throws Exception{
        // create message factory
        MessageFactory mf = MessageFactory.newInstance();
        // headers for a SOAP message
        MimeHeaders header = new MimeHeaders();
        header.addHeader("Content-Type", "text/xml");

        InputStream is = this.getClass().getResourceAsStream("/sample.xml");

        // create the SOAPMessage
        SOAPMessage soapMessage = mf.createMessage(header,is);
        SOAPHeader soapHeader = soapMessage.getSOAPHeader();
        // get the body
        SOAPBody soapBody = soapMessage.getSOAPBody();
        // find your node based on tag name
        NodeList nodes = soapHeader.getElementsByTagName("Response");
        System.out.println(nodes.getLength());
        // check if the node exists and get the value
        String someMsgContent = null;
        Node node = nodes.item(0);
        someMsgContent = node != null ? node.getTextContent() : "";
        Iterator<javax.xml.soap.Node> msg = soapHeader.getChildElements();
        while (msg.hasNext())
            System.out.println(msg.next().getLocalName());
    }

    public Response getSamlAssertion(String samlResponse) throws IOException, XMLParserException, UnmarshallingException {
        Response response = (Response) XMLObjectSupport.unmarshallFromInputStream(
                XMLObjectProviderRegistrySupport.getParserPool(), IOUtils.toInputStream(samlResponse, Charset.defaultCharset()));
        return response;

    }

    private Credential getSigningCredential() {
        try (InputStream inputStream = this.getClass().getResourceAsStream("/test.crt")) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            final Credential publicCredential = new BasicX509Credential(certificate);
            log.debug("getSigningCredential: key retrieved.");
            return publicCredential;
        } catch (final Exception ex) {
            log.error(ex.getMessage(), ex);
            return null;
        }
    }
}
