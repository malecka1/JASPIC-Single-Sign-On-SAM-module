# Server Authentication Module for Single Sign-On

  This project contains proof of concept of using JASPIC (Java Authentication Service Provider Interface for Containers) from Java EE Full Platform to create SAM (Server Authentication Module) which can serve as a Service Provider for Single Sign-On system using SAML (Security Assertion Markup Language) messages for communication. Tested with GlassFish and Shibboleth SSO. OpenSAML library is being used for dealing with SAML messages. Supported SAML Web Browser SSO Profile only.


### Configuration

  Output jar file with dependencies must be available to an application server. For example, for GlassFish it means to put the file in the <gf-install-dir>/glassfish/domains/<domain-name>/lib folder. The second step is a registration of the SAM module in the application server. This step can be done usually either by domain configuration file modification, or using graphic console.

  Usage of any SAM module must be configured in an application as well (e.g. glassfish-web.xml).


### License
  
  See *LICENSE* file.


### Developed By

  Malecek Kamil, 2016
