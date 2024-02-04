package com.zigaai.constants;

public final class SecurityConstant {

    private SecurityConstant() {
    }

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final class CacheKey {

        public static String REFRESH_TOKEN_INFO(String refreshToken) {
            return "refresh_token_info:" + refreshToken;
        }

        public static String USER_REFRESH_TOKEN(String userType, String username) {
            return userType.toLowerCase() + ":refresh_token:" + username;
        }

        public static String USER_SALT(String userType, String username) {
            return userType.toLowerCase() + ":salt:" + username;
        }

    }
}
