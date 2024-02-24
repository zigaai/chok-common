package com.zigaai.security.converter;

import com.zigaai.grpc.lib.AuthInfoRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper
public interface AuthRequestConvertor {

    AuthRequestConvertor INSTANCE = Mappers.getMapper(AuthRequestConvertor.class);

    @Mapping(target = "usernameBytes", ignore = true)
    @Mapping(target = "userTypeBytes", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(source = "userType", target = "userType")
    @Mapping(source = "username", target = "username")
    AuthInfoRequest of(String userType, String username);
    
}
