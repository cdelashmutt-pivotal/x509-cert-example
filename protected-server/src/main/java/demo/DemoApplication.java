package demo;

import java.io.IOException;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
public class DemoApplication extends WebMvcConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
    
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	@Configuration
	protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest()
			  //.authenticated()
			  .hasRole("USER")
			  .and()
			  .x509().subjectPrincipalRegex("CN=(.*?),");
		}
		
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth)
				throws Exception {
			auth.
				inMemoryAuthentication()
					.withUser("client").password("password").roles("USER");
		}

	}
	
    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer(
            @Value("${keystore.file}") final Resource keystoreFile,
            @Value("${keystore.alias}") final String keystoreAlias,
            @Value("${keystore.type}") final String keystoreType,
            @Value("${keystore.pass}") final String keystorePass,
            @Value("${truststore.file}") final Resource truststoreFile,
            @Value("${truststore.type}") final String truststoreType,
            @Value("${truststore.pass}") final String truststorePass,
            @Value("${tls.port}") final int tlsPort
    ) {
        return new EmbeddedServletContainerCustomizer() {
            @Override
            public void customize(ConfigurableEmbeddedServletContainer container) {
                if (container instanceof TomcatEmbeddedServletContainerFactory) {
                    TomcatEmbeddedServletContainerFactory containerFactory = (TomcatEmbeddedServletContainerFactory) container;
                    containerFactory.addConnectorCustomizers(new TomcatConnectorCustomizer() {
 
                        @Override
                        public void customize(Connector connector) {
 
                            connector.setPort(tlsPort);
                            connector.setSecure(true);
                            connector.setScheme("https");
                            connector.setAttribute("keyAlias", keystoreAlias);
                            connector.setAttribute("keystorePass", keystorePass);
                            String absoluteKeystoreFile;
                            try {
                                absoluteKeystoreFile = keystoreFile.getFile().getAbsolutePath();
                                connector.setAttribute("keystoreFile", absoluteKeystoreFile);
                            } catch (IOException e) {
                                throw new IllegalStateException("Cannot load keystore", e);
                            }
                            connector.setAttribute("clientAuth", "true");
                            connector.setAttribute("truststorePass", truststorePass);
                            String absoluteTruststoreFile;
                            try {
                            	absoluteTruststoreFile = truststoreFile.getFile().getAbsolutePath();
                                connector.setAttribute("truststoreFile", absoluteTruststoreFile);
                            } catch (IOException e) {
                                throw new IllegalStateException("Cannot load truststore", e);
                            }
                            connector.setAttribute("sslProtocol", "TLS");
                            connector.setAttribute("SSLEnabled", true);
 
                            Http11NioProtocol proto = (Http11NioProtocol) connector.getProtocolHandler();
                            proto.setSSLEnabled(true);
                            proto.setKeystoreFile(absoluteKeystoreFile);
                            proto.setKeystorePass(keystorePass);
                            proto.setKeystoreType(keystoreType);
                            proto.setKeyAlias(keystoreAlias);
                            proto.setTruststoreFile(absoluteTruststoreFile);
                            proto.setTruststorePass(truststorePass);
                            proto.setTruststoreType(truststoreType);
                        }
                    });
                }
            }
        };
    }
}