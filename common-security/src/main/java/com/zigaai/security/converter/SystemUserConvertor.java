package com.zigaai.security.converter;

import com.zigaai.model.security.AuthMenu;
import com.zigaai.model.security.AuthRole;
import com.zigaai.model.security.AuthenticationModel;
import com.zigaai.model.security.PayloadDTO;
import com.zigaai.security.model.SystemUser;
import com.zigaai.security.model.SystemUserVO;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.util.List;

@Mapper
public interface SystemUserConvertor {

    SystemUserConvertor INSTANCE = Mappers.getMapper(SystemUserConvertor.class);

    @Mapping(target = "iat", ignore = true)
    @Mapping(target = "exp", ignore = true)
    PayloadDTO toPayloadDTO(SystemUser systemUser, Long expiresIn, Long refreshExpiresIn);

    SystemUserVO toVO(SystemUser systemUser);

    @Mapping(source = "roleList", target = "roleList")
    @Mapping(source = "menuList", target = "menuList")
    @Mapping(target = "authorities", expression = "java(com.zigaai.security.utils.SecurityUtil.toAuthorities(roleList, menuList))")
    // @Mapping(target = "userType", expression = "java(com.foo.enumeration.SysUserType.ADMIN)")
    SystemUser from(AuthenticationModel admin, List<? extends AuthRole> roleList, List<? extends AuthMenu> menuList);

}