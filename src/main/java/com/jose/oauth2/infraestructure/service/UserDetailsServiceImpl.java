package com.jose.oauth2.infraestructure.service;

import com.jose.oauth2.infraestructure.client.UserFeignClient;
import com.jose.oauth2.model.response.LoadedUserSecurity;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserFeignClient client;

  @Override
  public UserDetails loadUserByUsername(String username)
    throws UsernameNotFoundException {

    LoadedUserSecurity user = this.client.loadUserByUsername(username);

    return new User(
      String.valueOf(user.getId()),
      user.getPassword(),
      user
        .getRoles()
        .stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toSet())
    );
  }
}
