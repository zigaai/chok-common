package com.zigaai.security.converter;

import com.zigaai.constants.SecurityConstant;
import com.zigaai.grpc.lib.AuthMenuReply;
import com.zigaai.grpc.lib.AuthRoleReply;
import com.zigaai.grpc.lib.SimpleGrantedAuthorityReply;
import com.zigaai.grpc.lib.SystemUserReply;
import com.zigaai.model.security.AuthMenu;
import com.zigaai.model.security.AuthRole;
import com.zigaai.model.security.AuthenticationModel;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.model.SystemUserVO;
import org.mapstruct.*;
import org.mapstruct.factory.Mappers;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

@Mapper
public interface SystemUserConvertor {

    SystemUserConvertor INSTANCE = Mappers.getMapper(SystemUserConvertor.class);

    @Mapping(target = "sub", ignore = true)
    @Mapping(target = "kid", ignore = true)
    @Mapping(target = SecurityConstant.TokenKey.IAT, ignore = true)
    @Mapping(target = SecurityConstant.TokenKey.AUD, source = "systemUser.username")
    @Mapping(target = SecurityConstant.TokenKey.EXP, source = "expiresIn")
    @Mapping(target = "expiresIn", source = "expiresIn")
    PayloadDTO toPayloadDTO(SystemUser systemUser, Long expiresIn, Long refreshExpiresIn);

    SystemUserVO toVO(SystemUser systemUser);

    @Mapping(target = "clientId", ignore = true)
    @Mapping(target = SecurityConstant.TokenKey.AUD, ignore = true)
    @Mapping(target = SecurityConstant.TokenKey.SCOPE, ignore = true)
    @Mapping(source = "roleList", target = "roleList")
    @Mapping(source = "menuList", target = "menuList")
    @Mapping(target = "authorities", expression = "java(com.zigaai.security.utils.SecurityUtil.toAuthorities(roleList, menuList))")
    // @Mapping(target = "userType", expression = "java(com.foo.enumeration.SysUserType.ADMIN)")
    SystemUser of(AuthenticationModel model, List<? extends AuthRole> roleList, List<? extends AuthMenu> menuList);

    @Mapping(target = "usernameBytes", ignore = true)
    @Mapping(target = "userTypeBytes", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "saltBytes", ignore = true)
    @Mapping(target = "removeRoleList", ignore = true)
    @Mapping(target = "removeMenuList", ignore = true)
    @Mapping(target = "removeAuthorities", ignore = true)
    @Mapping(target = "passwordBytes", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clientIdBytes", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(target = "roleListOrBuilderList", ignore = true)
    @Mapping(target = "roleListBuilderList", ignore = true)
    @Mapping(target = "menuListOrBuilderList", ignore = true)
    @Mapping(target = "menuListBuilderList", ignore = true)
    @Mapping(target = "authoritiesOrBuilderList", ignore = true)
    @Mapping(target = "authoritiesBuilderList", ignore = true)
    @Mapping(target = "audList", ignore = true)
    @Mapping(target = "scopeList", ignore = true)
    @Mapping(target = "roleListList", ignore = true)
    @Mapping(target = "menuListList", ignore = true)
    @Mapping(target = "authoritiesList", ignore = true)
    @Mapping(target = "clientId", ignore = true)
    SystemUserReply toRpcSystemUser(SystemUser systemUser);

    @InheritInverseConfiguration
    @Mapping(target = "aud", ignore = true)
    @Mapping(target = "scope", ignore = true)
    @Mapping(source = "roleListList", target = "roleList")
    @Mapping(source = "menuListList", target = "menuList")
    @Mapping(source = "authoritiesList", target = "authorities")
    SystemUser of(SystemUserReply systemUser);

    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    List<AuthRoleReply> toRpcRoleList(List<AuthRole> list);

    @InheritInverseConfiguration
    List<AuthRole> toRoleList(List<AuthRoleReply> list);

    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "roleCodeBytes", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    AuthRoleReply toRpcModel(AuthRole model);

    @InheritInverseConfiguration
    AuthRole toModel(AuthRoleReply rpcModel);

    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    List<AuthMenuReply> toRpcAuthMenuList(List<AuthMenu> list);

    @InheritInverseConfiguration
    List<AuthMenu> toAuthMenuList(List<AuthMenuReply> list);

    @Mapping(target = "nameBytes", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    AuthMenuReply toRpcModel(AuthMenu model);

    @InheritInverseConfiguration
    AuthMenu toModel(AuthMenuReply rpcModel);

    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    List<SimpleGrantedAuthorityReply> toRpcAuthorityList(Collection<? extends GrantedAuthority> authorities);

    @InheritInverseConfiguration
    List<SimpleGrantedAuthority> toAuthorityList(List<SimpleGrantedAuthorityReply> list);

    @Mapping(target = "roleBytes", ignore = true)
    @Mapping(target = "unknownFields", ignore = true)
    @Mapping(target = "mergeUnknownFields", ignore = true)
    @Mapping(target = "mergeFrom", ignore = true)
    @Mapping(target = "clearOneof", ignore = true)
    @Mapping(target = "clearField", ignore = true)
    @Mapping(target = "allFields", ignore = true)
    @Mapping(target = "role", source = "authority")
    SimpleGrantedAuthorityReply toRpcModel(GrantedAuthority model);

    @AfterMapping
    default void afterMapping(@MappingTarget SystemUserReply.Builder target, SystemUser systemUser) {
        target.addAllRoleList(toRpcRoleList(systemUser.getRoleList()));
        target.addAllMenuList(toRpcAuthMenuList(systemUser.getMenuList()));
        target.addAllAuthorities(toRpcAuthorityList(systemUser.getAuthorities()));
    }
}
