package com.jose.oauth2.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityConfig {

  private final UserDetailsService userDetailsService;

  public SecurityConfig(
    @Qualifier(
      value = "userDetailsServiceImpl"
    ) UserDetailsService userDetailsService
  ) {
    this.userDetailsService = userDetailsService;
  }

  @Value("${app.client.id}")
  private String clientId;

  @Value("${app.client.secret}")
  private String clientSecret;

  @Value("${app.client-scope-read}")
  private String scopeRead;

  @Value("${app.client-scope-write}")
  private String scopeWrite;

  @Value("${app.client-redirect-debugger}")
  private String redirectUri1;

  @Value("${app.client-redirect-spring-doc}")
  private String redirectUri2;

  private static final String LOGIN_RESOURCE = "/login";

  @Bean
  @Order(1)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
    throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
      OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
      .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
      .with(authorizationServerConfigurer, authorizationServer ->
        authorizationServer.oidc(Customizer.withDefaults())
      )
      .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()
      )
      .exceptionHandling(e ->
        e.authenticationEntryPoint(
          new LoginUrlAuthenticationEntryPoint(LOGIN_RESOURCE)
        )
      );

    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
    throws Exception {
    http
      .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()
      )
      .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  RegisteredClientRepository registeredClientRepository(
    BCryptPasswordEncoder encoder
  ) {
    var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(clientId)
      .clientSecret(encoder.encode(clientSecret))
      .scope(scopeRead)
      .scope(scopeWrite)
      .redirectUri(redirectUri1)
      .redirectUri(redirectUri2)
      .clientAuthenticationMethod(
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC
      )
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .postLogoutRedirectUri("http://localhost:8080/login")
      .build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  TokenSettings tokenSettings() {
    return TokenSettings.builder()
      .refreshTokenTimeToLive(Duration.ofHours(1))
      .build();
  }

  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
    return context -> {
      if (context.getTokenType().equals(context.getTokenType())) {
        context
          .getClaims()
          .claims(claims -> {
            Set<String> roles = AuthorityUtils.authorityListToSet(
              context.getPrincipal().getAuthorities()
            )
              .stream()
              .map(c -> c.replaceFirst("^ROLE_", ""))
              .collect(
                Collectors.collectingAndThen(
                  Collectors.toSet(),
                  Collections::unmodifiableSet
                )
              );
            claims.put("roles", roles);
          });
      }
    };
  }

  @Bean
  AuthenticationProvider provider(BCryptPasswordEncoder encoder) {
    DaoAuthenticationProvider authenticationProvider =
      new DaoAuthenticationProvider(encoder);
    authenticationProvider.setUserDetailsService(userDetailsService);
    return authenticationProvider;
  }

  @Bean
  BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
