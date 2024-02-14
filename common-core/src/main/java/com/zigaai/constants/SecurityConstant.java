package com.zigaai.constants;

public final class SecurityConstant {

    private SecurityConstant() {
    }

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final String PRE_AUTHORIZATION_HEADER = "Pre-Authorization";

    public static final class CacheKey {

        private CacheKey() {
        }

        @SuppressWarnings("squid:S100")
        public static String REFRESH_TOKEN_INFO(String refreshToken) {
            return "refresh_token_info:" + refreshToken;
        }

        @SuppressWarnings("squid:S100")
        public static String USER_REFRESH_TOKEN(String userType, String username) {
            return userType.toLowerCase() + ":refresh_token:" + username;
        }

        @SuppressWarnings("squid:S100")
        public static String USER_SALT(String userType, String username) {
            return userType.toLowerCase() + ":salt:" + username;
        }

    }

    public static final class TokenKey {

        private TokenKey() {
        }

        public static final String ID = "id";

        public static final String USER_TYPE = "userType";

        public static final String CLIENT_ID = "clientId";

        public static final String KID = "kid";

        public static final String SID = "sid";

        public static final String SUB = "sub";

        public static final String EXP = "exp";

        public static final String IAT = "iat";

        public static final String AUD = "aud";

        public static final String SCOPE = "scope";
    }
}
