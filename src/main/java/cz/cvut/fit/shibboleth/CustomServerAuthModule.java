package cz.cvut.fit.shibboleth;

import org.opensaml.xml.util.Pair;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Custom {@link ServerAuthModule} implementation for Shibboleth.
 */
public class CustomServerAuthModule implements ServerAuthModule {

    private static final Logger LOGGER = Logger.getLogger(CustomServerAuthModule.class.getName());

    private CallbackHandler callbackHandler;
    private boolean isProtectedResource;
    private Map options;

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        this.callbackHandler = handler;
        this.isProtectedResource = requestPolicy.isMandatory();
        this.options = options;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class[] getSupportedMessageTypes() {
        return new Class[]{HttpServletRequest.class, HttpServletResponse.class};
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        final HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
        final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpSession session = request.getSession(true); // create session if it doesn't exist
        final Principal principal = request.getUserPrincipal(); // inherit principal

        if (principal != null) { // already authenticated principal

            LOGGER.info("Principal authenticated.");
            try {
                callbackHandler.handle(new Callback[]{new CallerPrincipalCallback(clientSubject, principal)});
            } catch (IOException | UnsupportedCallbackException e) {
                LOGGER.warning("Could not use authenticated principal.");
                throw new AuthException();
            }
            return AuthStatus.SUCCESS;

        } else if (!isProtectedResource && session.getAttribute(AuthenticationService.getIdSessionName()) == null) { // unprotected resource

            LOGGER.info("Unprotected resource.");
            return AuthStatus.SUCCESS;

        } else { // authenticate, use session to remember data and get user with groups

            final AuthenticationService authenticationService = new AuthenticationService(options);

            if (session.getAttribute(AuthenticationService.getIdSessionName()) == null) { // create AuthnRequest

                LOGGER.info("Create AuthnRequest.");
                try {
                    authenticationService.createAuthnRequest(request, response);
                } catch (Exception e) {
                    LOGGER.warning("AuthnRequest creation failed.");
                    throw new AuthException();
                }
                return AuthStatus.SEND_CONTINUE;

            } else { // consume AuthnResponse

                LOGGER.info("Process AuthnResponse.");
                final Pair<String, String[]> usernameGroups;
                try {
                    usernameGroups = authenticationService.consumeAuthnResponse(request, response);
                } catch (Exception e) {
                    LOGGER.warning("AuthnResponse processing failed.");
                    throw new AuthException();
                }

                messageInfo.getMap().put("javax.servlet.http.registerSession", Boolean.TRUE.toString()); // allow principal storing

                try {
                    callbackHandler.handle(new Callback[]{new CallerPrincipalCallback(clientSubject, usernameGroups.getFirst()), new GroupPrincipalCallback(clientSubject, usernameGroups.getSecond())});
                } catch (IOException | UnsupportedCallbackException e) {
                    LOGGER.warning("Could not authenticate user.");
                    throw new AuthException();
                }
                return AuthStatus.SUCCESS;

            }

        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        try {
            request.logout();
        } catch (ServletException e) {
            LOGGER.warning("Could not logout.");
            throw new AuthException();
        }

        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        LOGGER.info("Logout successful.");
    }
}
