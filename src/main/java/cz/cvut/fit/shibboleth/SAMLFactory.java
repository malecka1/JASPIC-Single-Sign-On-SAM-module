package cz.cvut.fit.shibboleth;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

import javax.xml.namespace.QName;

/**
 * OpenSAML factory class.
 */
public class SAMLFactory {

    /**
     * OpenSAML initialization.
     */
    public SAMLFactory() {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException("Cannot initialize OpenSAML library.", e);
        }
    }

    /**
     * An easy way to create objects using OpenSAML builder system.
     */
    protected <T> T create(Class<T> tClass, QName qname) {
        return (T) Configuration.getBuilderFactory().getBuilder(qname).buildObject(qname);
    }
}
