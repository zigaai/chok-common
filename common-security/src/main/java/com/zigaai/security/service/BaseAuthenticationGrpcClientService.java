package com.zigaai.security.service;

import com.zigaai.grpc.lib.AuthInfoRequest;
import com.zigaai.grpc.lib.AuthServiceGrpc;
import com.zigaai.grpc.lib.SystemUserReply;
import com.zigaai.security.model.SystemUser;

public abstract class BaseAuthenticationGrpcClientService extends AuthServiceGrpc.AuthServiceImplBase implements AuthenticationService {

    @Override
    public String getSalt(String userType, String username) {
        AuthInfoRequest request = AuthInfoRequest.newBuilder()
                .setUserType(userType)
                .setUsername(username)
                .build();
        return getBlockingStub().getSalt(request).getVal();
    }

    @Override
    public SystemUser loadUserByUsername(String userType, String username) {
        AuthInfoRequest request = AuthInfoRequest.newBuilder()
                .setUserType(userType)
                .setUsername(username)
                .build();
        SystemUserReply reply = getBlockingStub().loadUserByUsername(request);
        return SystemUser.of(reply);
    }

    public abstract AuthServiceGrpc.AuthServiceBlockingStub getBlockingStub();

}
