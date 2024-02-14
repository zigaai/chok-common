package com.zigaai.security.provider;

import com.zigaai.security.model.SystemUser;
import com.zigaai.security.processor.usernamepassword.SysUsernamePasswordToken;
import com.zigaai.security.properties.CustomSecurityProperties;
import com.zigaai.security.service.AuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

// @formatter:off
@Slf4j
@SuppressWarnings("squid:S125")
public class DaoMultiAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    /**
     * The plaintext password used to perform
     * {@link PasswordEncoder#matches(CharSequence, String)} on when the user is not found
     * to avoid SEC-2056.
     */
    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

    private PasswordEncoder passwordEncoder;

    /**
     * The password used to perform {@link PasswordEncoder#matches(CharSequence, String)}
     * on when the user is not found to avoid SEC-2056. This is necessary, because some
     * {@link PasswordEncoder} implementations will short circuit if the password is not
     * in a valid format.
     */
    private volatile String userNotFoundEncodedPassword;

    private final AuthenticationService authenticationService;

    private final CustomSecurityProperties customSecurityProperties;

    // private UserDetailsPasswordService userDetailsPasswordService;

    private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    public DaoMultiAuthenticationProvider(AuthenticationService authenticationService,
                                          CustomSecurityProperties customSecurityProperties) {
        this(new BCryptPasswordEncoder(), authenticationService, customSecurityProperties);
    }

    /**
     * Creates a new instance using the provided {@link PasswordEncoder}
     * @param passwordEncoder the {@link PasswordEncoder} to use. Cannot be null.
     * @since 6.0.3
     */
    public DaoMultiAuthenticationProvider(PasswordEncoder passwordEncoder,
                                          AuthenticationService authenticationService,
                                          CustomSecurityProperties customSecurityProperties) {
        setPasswordEncoder(passwordEncoder);
        this.authenticationService = authenticationService;
        this.customSecurityProperties = customSecurityProperties;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        String presentedPassword = authentication.getCredentials().toString();
        if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            this.logger.debug("Failed to authenticate since password does not match stored value");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

    @Override
    protected void doAfterPropertiesSet() {
        Assert.notNull(this.authenticationService, "A UserDetailsService must be set");
    }

    @Override
    protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        prepareTimingAttackProtection();
        CustomSecurityProperties.Context userType = ((SysUsernamePasswordToken)authentication).getUserType();
        // SysUserType userType = ((SysUsernamePasswordToken)authentication).getUserType();
        try {
            UserDetails loadedUser = authenticationService.loadUserByUsername(userType.getCode(), username);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        }
        catch (UsernameNotFoundException ex) {
            mitigateAgainstTimingAttack(authentication);
            throw ex;
        }
        catch (InternalAuthenticationServiceException ex) {
            throw ex;
        }
        catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
                                                         UserDetails user) {
        // boolean upgradeEncoding = this.userDetailsPasswordService != null
        //         && this.passwordEncoder.upgradeEncoding(user.getPassword());
        // if (upgradeEncoding) {
        //     String presentedPassword = authentication.getCredentials().toString();
        //     String newPassword = this.passwordEncoder.encode(presentedPassword);
        //     user = this.userDetailsPasswordService.updatePassword(user, newPassword);
        // }
        SystemUser systemUser = (SystemUser) user;
        CustomSecurityProperties.Context userType = customSecurityProperties.getUserType(systemUser.getUserType());
        SysUsernamePasswordToken result = SysUsernamePasswordToken.authenticated(principal, authentication.getCredentials(),
                userType, this.authoritiesMapper.mapAuthorities(systemUser.getAuthorities()));
        result.setDetails(authentication.getDetails());
        this.logger.debug("Authenticated user");
        return result;
        // return super.createSuccessAuthentication(principal, authentication, user);
    }

    @SuppressWarnings("squid:S6437")
    private void prepareTimingAttackProtection() {
        if (this.userNotFoundEncodedPassword == null) {
            this.userNotFoundEncodedPassword = this.passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
        }
    }

    private void mitigateAgainstTimingAttack(UsernamePasswordAuthenticationToken authentication) {
        if (authentication.getCredentials() != null) {
            String presentedPassword = authentication.getCredentials().toString();
            this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
        }
    }

    /**
     * Sets the PasswordEncoder instance to be used to encode and validate passwords. If
     * not set, the password will be compared using
     * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
     * @param passwordEncoder must be an instance of one of the {@code PasswordEncoder}
     * types.
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
        this.passwordEncoder = passwordEncoder;
        this.userNotFoundEncodedPassword = null;
    }

    protected PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }

    // public void setUserDetailsPasswordService(UserDetailsPasswordService userDetailsPasswordService) {
    //     this.userDetailsPasswordService = userDetailsPasswordService;
    // }

}
