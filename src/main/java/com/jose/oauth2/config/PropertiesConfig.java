package com.jose.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;

@Configuration
@PropertySources(
  { @PropertySource(value = "classpath:configs/client-security.properties") }
)
public class PropertiesConfig {}
