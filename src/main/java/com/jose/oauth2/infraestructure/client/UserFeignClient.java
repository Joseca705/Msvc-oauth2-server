package com.jose.oauth2.infraestructure.client;

import com.jose.oauth2.model.response.LoadedUserSecurity;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "msvc-users")
public interface UserFeignClient {
  @GetMapping("/user/username/{username}")
  LoadedUserSecurity loadUserByUsername(@PathVariable String username);
}
