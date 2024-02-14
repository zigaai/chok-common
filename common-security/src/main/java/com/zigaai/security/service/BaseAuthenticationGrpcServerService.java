package com.zigaai.security.service;

import com.zigaai.exception.BizIllegalArgumentException;
import com.zigaai.grpc.lib.*;
import com.zigaai.model.security.AuthMenu;
import com.zigaai.model.security.AuthRole;
import com.zigaai.security.model.SystemUser;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

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
        List<AuthRole> roleList = systemUser.getRoleList();
        List<AuthRoleReply> authRoleList = Collections.emptyList();
        if (!CollectionUtils.isEmpty(roleList)) {
            authRoleList = new ArrayList<>(roleList.size());
            for (AuthRole item : roleList) {
                authRoleList.add(AuthRoleReply.newBuilder()
                        .setRoleCode(item.getRoleCode())
                        .build()
                );
            }
        }
        List<AuthMenu> menuList = systemUser.getMenuList();
        List<AuthMenuReply> authMenuList = Collections.emptyList();
        if (!CollectionUtils.isEmpty(menuList)) {
            authMenuList = new ArrayList<>(roleList.size());
            for (AuthMenu item : menuList) {
                authMenuList.add(AuthMenuReply.newBuilder()
                        .setName(item.getName())
                        .build());
            }
        }
        Collection<? extends GrantedAuthority> authorities = systemUser.getAuthorities();
        List<SimpleGrantedAuthorityReply> simpleAuthorities = Collections.emptyList();
        if (!CollectionUtils.isEmpty(authorities)) {
            simpleAuthorities = new ArrayList<>(authorities.size());
            for (GrantedAuthority item : authorities) {
                simpleAuthorities.add(SimpleGrantedAuthorityReply.newBuilder()
                        .setRole(item.getAuthority())
                        .build());
            }
        }
        SystemUserReply reply = SystemUserReply.newBuilder()
                .setId(systemUser.getId())
                .setUsername(systemUser.getUsername())
                .setIsDeleted(systemUser.getIsDeleted())
                .setUserType(systemUser.getUserType())
                .addAllRoleList(authRoleList)
                .addAllMenuList(authMenuList)
                .addAllAuthorities(simpleAuthorities)
                .build();
        responseObserver.onNext(reply);
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
