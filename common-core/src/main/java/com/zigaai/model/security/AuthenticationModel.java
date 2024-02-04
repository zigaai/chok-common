package com.zigaai.model.security;

public interface AuthenticationModel {

    Long getId();

    String getUsername();

    String getPassword();

    String getSalt();

    Boolean getIsDeleted();

    String getUserType();

}
