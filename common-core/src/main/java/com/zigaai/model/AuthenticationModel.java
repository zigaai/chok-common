package com.zigaai.model;

public interface AuthenticationModel {

    Long getId();

    String getUsername();

    String getPassword();

    String getSalt();

    Boolean getIsDeleted();

    String getUserType();

}
