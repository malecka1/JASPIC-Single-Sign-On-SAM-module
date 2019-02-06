package cz.cvut.fit.shibboleth;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.validation.ValidationException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.message.AuthException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Creates {@link AuthnRequest} and consumes AuthnResponse used in the communication with Shibboleth Identity Provider.
 */
public class AuthenticationService extends SAMLFactory {

    private static final Logger LOGGER = Logger.getLogger(AuthenticationService.class.getName());

    private static final String ID_SESSION_NAME = "ID";
    private static final String IV_SESSION_NAME = "IV";
    private static final String RELAY_STATE_PARAM_NAME = "RelayState";
    private static final String HASH_ALGORITHM = "SHA-1";
    private static final String ENCRYPT_ALGORITHM = "AES";
    private static final String ENCRYPT_TRANSFORMATION = "AES/CBC/PKCS5PADDING";

    private static final String ACS_URL_KEY = "ACS_URL";
    private static final String IDP_CRT_PATH_KEY = "IDP_CRT_PATH";
    private static final String ISSUER_KEY = "ISSUER";
    private static final String KEYSTORE_PASSWORD_KEY = "KEYSTORE_PASSWORD";
    private static final String KEYSTORE_PATH_KEY = "KEYSTORE_PATH";
    private static final String PRIVATE_KEY_ALIAS_KEY = "PRIVATE_KEY_ALIAS";
    private static final String PRIVATE_KEY_PASSWORD_KEY = "PRIVATE_KEY_PASSWORD";
    private static final String SSO_REDIRECT_ENDPOINT_KEY = "SSO_ENDPOINT";

    private final String ACS_URL;
    private final String IDP_CRT_PATH;
    private final String ISSUER;
    private final String KEYSTORE_PASSWORD;
    private final String KEYSTORE_PATH;
    private final String PRIVATE_KEY_ALIAS;
    private final String PRIVATE_KEY_PASSWORD;
    private final String SSO_REDIRECT_ENDPOINT;

    // SAML attributes names
    private static final String UID_ATTRIBUTE_NAME = "urn:oid:0.9.2342.19200300.100.1.1";
    private static final String EMPLOYEETYPE_ATTRIBUTE_NAME = "urn:oid:2.16.840.1.113730.3.1.4";

    /**
     * Constructor sets important configuration from module's properties map.
     *
     * @param options map with configuration
     */
    AuthenticationService(Map options) {
        super();
        this.ACS_URL = String.valueOf(options.get(ACS_URL_KEY));
        this.IDP_CRT_PATH = String.valueOf(options.get(IDP_CRT_PATH_KEY));
        this.ISSUER = String.valueOf(options.get(ISSUER_KEY));
        this.KEYSTORE_PASSWORD = String.valueOf(options.get(KEYSTORE_PASSWORD_KEY));
        this.KEYSTORE_PATH = String.valueOf(options.get(KEYSTORE_PATH_KEY));
        this.PRIVATE_KEY_ALIAS = String.valueOf(options.get(PRIVATE_KEY_ALIAS_KEY));
        this.PRIVATE_KEY_PASSWORD = String.valueOf(options.get(PRIVATE_KEY_PASSWORD_KEY));
        this.SSO_REDIRECT_ENDPOINT = String.valueOf(options.get(SSO_REDIRECT_ENDPOINT_KEY));
    }

    /**
     * @return session parameter name for the {@link AuthnRequest}'s ID
     */
    public static String getIdSessionName() {
        return ID_SESSION_NAME;
    }

    /**
     * XORShift random number generator.
     *
     * @return generated value
     * @see <a href="http://www.javamex.com/tutorials/random_numbers/xorshift.shtml">Javamex XORShift</a>
     */
    private long getRandomLong() {
        long random = System.nanoTime();
        random ^= (random << 21);
        random ^= (random >>> 35);
        random ^= (random << 4);
        return random;
    }

    /**
     * Create hash of the input using SHA-1.
     *
     * @param input input
     * @return SHA-1 hash
     * @throws AuthException when processing failed
     */
    private String getSHAHash(long input) throws AuthException {
        final MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warning("Invalid hash algorithm.");
            throw new AuthException();
        }
        messageDigest.update(String.valueOf(input).getBytes());
        final byte byteData[] = messageDigest.digest();
        final StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            stringBuffer.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    /**
     * Create {@link RelayState} parameter.
     *
     * @param request request
     * @return RelayState value
     * @throws AuthException when processing failed
     */
    private String createRelayState(HttpServletRequest request) throws AuthException {
        final HttpSession session = request.getSession(false);

        final String sessionId = session.getId().substring(0, 24); // use 24 bytes key for AES, default GlassFish sessionId is 28 bytes
        final SecretKeySpec key = new SecretKeySpec(sessionId.getBytes(), ENCRYPT_ALGORITHM);
        final Cipher cipher;
        final byte[] encrypted;
        try {
            cipher = Cipher.getInstance(ENCRYPT_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(request.getRequestURL().toString().getBytes());
        } catch (Exception e) {
            LOGGER.warning("RelayState encryption failed.");
            throw new AuthException();
        }

        final String relayState = new String(Base64.encodeBytes(encrypted));
        session.setAttribute(IV_SESSION_NAME, cipher.getIV()); // Initialization Vector
        return relayState;
    }

    /**
     * Create and encode {@link AuthnRequest} and {@link RelayState}, set as parameters of the request to the IdP.
     *
     * @param request  request
     * @param response response
     * @throws AuthException when processing failed
     */
    public void createAuthnRequest(HttpServletRequest request, HttpServletResponse response) throws AuthException {
        final BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> messageContext = new BasicSAMLMessageContext<>();

        // Endpoint
        final SingleSignOnService endpoint = create(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        endpoint.setLocation(SSO_REDIRECT_ENDPOINT);
        messageContext.setPeerEntityEndpoint(endpoint);

        // AuthnRequest
        final AuthnRequest authnRequest = create(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setAssertionConsumerServiceURL(ACS_URL);

        // ID
        final String idHash = getSHAHash(getRandomLong());
        request.getSession(false).setAttribute(ID_SESSION_NAME, idHash);
        authnRequest.setID(idHash);

        // Date, version
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setVersion(SAMLVersion.VERSION_20);

        // Issuer
        final Issuer issuer = create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(ISSUER);
        authnRequest.setIssuer(issuer);

        // AllowCreate should be true due to better interoperability
        final NameIDPolicy nameIDPolicy = create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setAllowCreate(new XSBooleanValue(true, true));
        authnRequest.setNameIDPolicy(nameIDPolicy);

        // RelayState, SAMLRequest params
        messageContext.setRelayState(createRelayState(request));
        messageContext.setOutboundSAMLMessage(authnRequest);

        // ResponseAdapter
        final HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(response, true);
        messageContext.setOutboundMessageTransport(responseAdapter);

        // Encoding
        final HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        try {
            encoder.encode(messageContext);
        } catch (MessageEncodingException e) {
            LOGGER.warning("AuthnRequest encoding failed.");
            throw new AuthException();
        }
    }

    /**
     * Decode {@link Response}, check IDs, {@link StatusCode} and get values of the uid and employeeType attributes.
     * Also get target resource URL from the {@link RelayState} parameter.
     *
     * @param request  request
     * @param response response
     * @return pair of user and groups
     * @throws AuthException when processing failed
     */
    public Pair<String, String[]> consumeAuthnResponse(HttpServletRequest request, HttpServletResponse response) throws AuthException {
        final HttpSession session = request.getSession(false);

        // Encrypt RelayState and get outbound URL
        final String sessionId = session.getId().substring(0, 24); // use 24 bytes key for AES, default GlassFish sessionId is 28 bytes
        final Key key = new SecretKeySpec(sessionId.getBytes(), ENCRYPT_ALGORITHM);
        final Cipher cipher;
        final String decryptedUrl;
        try {
            cipher = Cipher.getInstance(ENCRYPT_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec((byte[]) session.getAttribute(IV_SESSION_NAME)));
            final byte[] decoded = Base64.decode(request.getParameterMap().get(RELAY_STATE_PARAM_NAME)[0]);
            decryptedUrl = new String(cipher.doFinal(decoded));
        } catch (Exception e) {
            LOGGER.warning("RelayState decryption failed.");
            throw new AuthException();
        }

        // Get message context
        final MessageContext messageContext = new BasicSAMLMessageContext();
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        final HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder();
        try {
            httpPostDecoder.decode(messageContext);
        } catch (Exception e) {
            LOGGER.warning("AuthnResponse decoding failed.");
            throw new AuthException();
        }

        // Get SAML response and check value of 'inResponseTo' attribute
        final Response samlResponse = (Response) messageContext.getInboundMessage();
        if (!samlResponse.getInResponseTo().equals(String.valueOf(session.getAttribute(ID_SESSION_NAME)))) {
            LOGGER.warning("Attribute 'InResponseTo' of AuthnResponse doesn't match 'ID' of AuthnRequest.");
            throw new AuthException();
        }

        // Check status code
        if (!samlResponse.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
            LOGGER.warning("AuthnResponse does not contain 'success_uri' StatusCode.");
            throw new AuthException();
        }

        // Get SP private key
        final RSAPrivateKey privateKey;
        try {
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            privateKey = (RSAPrivateKey) keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD.toCharArray());
        } catch (Exception e) {
            LOGGER.warning("Unable to load a keystore.");
            throw new AuthException();
        }

        // Create decrypter
        final BasicX509Credential decryptionCredential = new BasicX509Credential();
        decryptionCredential.setPrivateKey(privateKey);
        final StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(decryptionCredential);
        final Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(Boolean.TRUE); // decrypted Assertion will have properly rooted DOM that allow signature verification!

        // Decrypt assertion
        final Assertion decryptedAssertion;
        try {
            decryptedAssertion = decrypter.decrypt(samlResponse.getEncryptedAssertions().get(0));
        } catch (DecryptionException e) {
            LOGGER.warning("Assertion decryption failed.");
            throw new AuthException();
        }

        // Get IdP certificate, extract public key
        final X509Certificate certificateIdP;
        try (final FileInputStream inputStream = new FileInputStream(IDP_CRT_PATH)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance(XMLX509Certificate.JCA_CERT_ID);
            certificateIdP = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            LOGGER.warning("Unable to get IdP certificate.");
            throw new AuthException();
        }
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificateIdP.getPublicKey().getEncoded());
        final PublicKey publicKeyIdP;
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKeyIdP = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            LOGGER.warning("Unable to get IdP public key.");
            throw new AuthException();
        }

        // Create SignatureValidator
        final BasicX509Credential publicIdPCredential = new BasicX509Credential();
        publicIdPCredential.setPublicKey(publicKeyIdP);
        final SignatureValidator signatureValidator = new SignatureValidator(publicIdPCredential);
        final Signature signature = decryptedAssertion.getSignature();

        // Validate signature
        try {
            signatureValidator.validate(signature);
        } catch (ValidationException e) {
            LOGGER.warning("Signature validation failed.");
            throw new AuthException();
        }

        // Get user and groups
        String uid = StringUtils.EMPTY;
        final List<String> employeeTypeList = new ArrayList<>();
        final List<AttributeStatement> attributeStatements = decryptedAssertion.getAttributeStatements(); // AttributeStatement section
        for (AttributeStatement attributeStatement : attributeStatements) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                final String attributeName = attribute.getDOM().getAttribute("Name");
                if (UID_ATTRIBUTE_NAME.equals(attributeName)) { // UID attribute
                    uid = attribute.getAttributeValues().get(0).getDOM().getTextContent();
                } else if (EMPLOYEETYPE_ATTRIBUTE_NAME.equals(attributeName)) { // EMPLOYEETYPE attribute
                    for (XMLObject xmlObject : attribute.getAttributeValues()) {
                        employeeTypeList.add(xmlObject.getDOM().getTextContent());
                    }
                }
            }
        }

        // Final redirect
        try {
            response.sendRedirect(decryptedUrl);
        } catch (IOException e) {
            LOGGER.warning("Unsuccessful redirect.");
            throw new AuthException();
        }

        String[] groups = new String[employeeTypeList.size()];
        groups = employeeTypeList.toArray(groups);
        return new Pair<>(uid, groups);
    }
}
