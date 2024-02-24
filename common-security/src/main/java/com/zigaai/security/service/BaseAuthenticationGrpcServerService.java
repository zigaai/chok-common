package com.zigaai.security.service;

import com.zigaai.exception.BizIllegalArgumentException;
import com.zigaai.grpc.lib.AuthInfoRequest;
import com.zigaai.grpc.lib.AuthServiceGrpc;
import com.zigaai.grpc.lib.GrpcString;
import com.zigaai.grpc.lib.SystemUserReply;
import com.zigaai.security.converter.SystemUserConvertor;
import com.zigaai.security.model.SystemUser;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.StringUtils;

public abstract class BaseAuthenticationGrpcServerService extends AuthServiceGrpc.AuthServiceImplBase implements AuthenticationService {

    @Override
    public void getSalt(AuthInfoRequest request, StreamObserver<GrpcString> responseObserver) {
        this.validateAuthInfo(request);
        String userType = request.getUserType();
        String username = request.getUsername();
        String salt = this.getSalt(userType, username);
        GrpcString reply = GrpcString.newBuilder()
                .setVal(salt)
                .build();
        responseObserver.onNext(reply);
        responseObserver.onCompleted();
    }

    @Override
    public void loadUserByUsername(AuthInfoRequest request, StreamObserver<SystemUserReply> responseObserver) {
        this.validateAuthInfo(request);
        String userType = request.getUserType();
        String username = request.getUsername();
        SystemUser systemUser = this.loadUserByUsername(userType, username);
        SystemUserReply rpcSystemUser = SystemUserConvertor.INSTANCE.toRpcSystemUser(systemUser);
        responseObserver.onNext(rpcSystemUser);
        responseObserver.onCompleted();
    }

    protected void validateAuthInfo(AuthInfoRequest request) {
        String userType = request.getUserType();
        if (StringUtils.isBlank(userType)) {
            throw new BizIllegalArgumentException("用户类型不可为空");
        }
        String username = request.getUsername();
        if (StringUtils.isBlank(username)) {
            throw new BizIllegalArgumentException("用户名不可为空");
        }
    }
}
