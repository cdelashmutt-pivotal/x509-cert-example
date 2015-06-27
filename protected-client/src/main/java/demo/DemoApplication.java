package demo;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class DemoApplication implements CommandLineRunner {

	@Value("${protected-server.url:https://localhost:8888/secure/secure}")
	private String protectedServerURL;
	
	@Value("${trustStoreResource:}")
	private Resource trustStoreResource;
	
	@Value("${trustStorePassword:}")
	private String trustStorePassword;

	@Value("${keyStoreResource:}")
	private Resource keyStoreResource;

	@Value("${keyStorePassword:}")
	private String keyStorePassword;

	@Autowired
	private RestTemplate restTemplate;

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Override
	public void run(String... strings) throws Exception {
		String quote = restTemplate.getForObject(protectedServerURL,
				String.class);
		System.out.println(quote.toString());
	}

	@Bean
	public RestTemplate restTemplate() throws GeneralSecurityException,
			IOException {
		RestTemplate restTemplate = new RestTemplate(clientRequestFactory());
		return restTemplate;
	}

	@Bean
	public ClientHttpRequestFactory clientRequestFactory()
			throws GeneralSecurityException, IOException {
		return new HttpComponentsClientHttpRequestFactory(httpClient());
	}

	@Bean
	public HttpClient httpClient() throws GeneralSecurityException, IOException {
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

		// THIS CODE IS INSECURE! It trusts any cert that the server decides to
		// give, which would make this client much more vulnerable to man in the
		// middle attacks. It is intended to get things going easily, but should
		// be quickly replaced when you can get the Root CA cert for your remote
		// service.

		// INSECURE
		TrustStrategy allTrust = new TrustStrategy() {
			@Override
			public boolean isTrusted(X509Certificate[] chain, String authType)
					throws CertificateException {
				return true;
			}
		};

		SSLContextBuilder sslcontextBuilder = SSLContexts.custom().useProtocol("TLS")
				.loadTrustMaterial(trustStore, allTrust);
		// END INSECURE

		// The better way to handle this would be to use the commented code
		// below to use a trust store that has the root CA for your remote
		// service imported into it.

		// MORE SECURE
//		SSLContextBuilder sslcontextBuilder = SSLContexts.custom().useProtocol("TLS")
//				.loadTrustMaterial(trustStoreResource.getURL(), trustStorePassword.toCharArray());
		// END MORE SECURE
		
		SSLContext sslcontext = sslcontextBuilder
				.loadKeyMaterial(keyStoreResource.getURL(), keyStorePassword.toCharArray(), keyStorePassword.toCharArray())
				.build();
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
				sslcontext,
				new DefaultHostnameVerifier());
		CloseableHttpClient httpClient = HttpClients.custom()
				.setSSLSocketFactory(sslsf).build();

		return httpClient;
	}
}