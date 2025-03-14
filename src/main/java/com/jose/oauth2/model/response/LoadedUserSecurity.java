package com.jose.oauth2.model.response;

import java.io.Serializable;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoadedUserSecurity implements Serializable {

  private Integer id;

  private String firstName;

  private String lastName;

  private String username;

  private String password;

  private List<String> roles;
}
