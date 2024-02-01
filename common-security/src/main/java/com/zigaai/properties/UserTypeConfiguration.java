// package com.zigaai.properties;
//
// import lombok.Getter;
// import lombok.Setter;
// import lombok.ToString;
// import org.springframework.boot.context.properties.ConfigurationProperties;
//
// import java.io.Serializable;
// import java.util.Map;
//
// @Getter
// @Setter
// @ToString
// @ConfigurationProperties(prefix = "system")
// public class UserTypeConfiguration implements Serializable {
//
//     /**
//      * 配置用户类型
//      */
//     private Map<String, Context> userType;
//
//     public Context getByCode(String code) {
//         return userType.get(code);
//     }
//
//     @Getter
//     @Setter
//     @ToString
//     public static class Context {
//
//         /**
//          * 用户类型值
//          */
//         private Byte val;
//
//         /**
//          * 用户类型code
//          */
//         private String code;
//
//         /**
//          * 用户角色关联表表名
//          */
//         private String relationTable;
//
//         /**
//          * 用户角色关联表关联ID
//          */
//         private String relationId;
//     }
//
// }
