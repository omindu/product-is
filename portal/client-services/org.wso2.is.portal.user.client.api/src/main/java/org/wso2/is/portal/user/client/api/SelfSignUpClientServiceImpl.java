/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.is.portal.user.client.api;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.identity.mgt.User;
import org.wso2.carbon.identity.mgt.bean.UserBean;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.impl.util.IdentityMgtConstants;
import org.wso2.carbon.identity.recovery.IdentityRecoveryClientException;
import org.wso2.carbon.identity.recovery.IdentityRecoveryException;
import org.wso2.carbon.identity.recovery.bean.NotificationResponseBean;
import org.wso2.carbon.identity.recovery.model.Property;
import org.wso2.carbon.identity.recovery.signup.UserSelfSignUpManager;
import org.wso2.is.portal.user.client.api.exception.UserPortalUIException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.ErrorCodes;

/**
 * Self sign up client service implementation.
 */
@Component(
        name = "org.wso2.is.portal.user.client.api.SelfSignUpClientServiceImpl",
        service = SelfSignUpClientService.class,
        immediate = true)
public class SelfSignUpClientServiceImpl implements SelfSignUpClientService {

    private UserSelfSignUpManager userSelfSignUpManager;

    private static final Logger log = LoggerFactory.getLogger(SelfSignUpClientServiceImpl.class);
    private RealmService realmService;

    @Reference(
            name = "userSelfSignUpManager",
            service = UserSelfSignUpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserSelfSignUpManager")
    public void userSelfSignUpManager(UserSelfSignUpManager userSelfSignUpManager) {

        this.userSelfSignUpManager = userSelfSignUpManager;
    }

    public void unsetUserSelfSignUpManager(UserSelfSignUpManager userSelfSignUpManager) {

        this.userSelfSignUpManager = null;
    }

    @Reference(
            name = "realmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {

        this.realmService = null;
    }

    @Override
    public NotificationResponseBean registerUser(Map<String, String> userClaims, Map<String, String> credentials,
                                         String domain, Map<String, String> properties) throws UserPortalUIException {

        try {

            UserBean userBean = new UserBean();

            List<Callback> credentialsList = credentials.entrySet()
                                                        .stream()
                                                        .map((x) -> {
                                                            PasswordCallback passwordCallback = new PasswordCallback
                                                                    ("password", false);
                                                            passwordCallback.setPassword(x.getValue().toCharArray());
                                                            return passwordCallback;
                                                        }).collect(Collectors.toList());

            List<Claim> claimsList = userClaims.entrySet()
                                               .stream()
                                               .map(x -> new Claim(IdentityMgtConstants.CLAIM_ROOT_DIALECT,
                                                               x.getKey(), x.getValue())).collect(Collectors.toList());

            userBean.setClaims(claimsList);
            userBean.setCredentials(credentialsList);

            Property[] props = properties.entrySet().stream()
                                         .map(x -> new Property(x.getKey(), x.getValue()))
                                         .toArray(Property[]::new);

            return userSelfSignUpManager.registerUser(userBean, domain, props);
        } catch (IdentityRecoveryClientException e) {

            if (log.isDebugEnabled()) {
                log.debug("Error occurred during user self sign-up.", e);
            }
            throw new UserPortalUIException("Error occurred during user self sign-up.");
        } catch (IdentityRecoveryException e) {
            log.error("Server error occurred during user self sign-up.", e);
            throw new UserPortalUIException("Error occurred during user self sign-up.");
        }
    }

    @Override
    public NotificationResponseBean resendConfirmationCode(String uniqueUserId, Map<String, String> properties)
            throws UserPortalUIException {
        IdentityStore identityStore = realmService.getIdentityStore();

        try {
            User user = identityStore.getUser(uniqueUserId);

            MetaClaim claim = new MetaClaim(IdentityMgtConstants.CLAIM_ROOT_DIALECT, IdentityMgtConstants
                    .USERNAME_CLAIM);
            List<MetaClaim> claims = new ArrayList<>(1);
            claims.add(claim);
            List<Claim> userClaims = user.getClaims(claims);

            if (userClaims == null || userClaims.isEmpty()) {
                log.error("Username claim cannot be found for user: " + uniqueUserId);
                throw new UserPortalUIException("Error occurred while retrieving user information.");
            }

            return resendConfirmationCode(userClaims.get(0), user.getDomainName(), properties);

        } catch (IdentityStoreException e) {
            log.error("Error occurred while retrieving user: " + uniqueUserId, e);
            throw new UserPortalUIException("Error occurred while retrieving user.");
        } catch (UserNotFoundException e) {
            log.error("User not found for ID: " + uniqueUserId, e);
            throw new UserPortalUIException("User could not be found.");
        }
    }

    @Override
    public void confirmUserSelfSignUp(String code) throws UserPortalUIException {

        try {
            userSelfSignUpManager.confirmUserSelfSignUp(code);
        }  catch (IdentityRecoveryClientException e) {

            if (ErrorCodes.EXPIRED_CODE.getCode().equals(e.getErrorCode())) {
                if (log.isDebugEnabled()) {
                    log.debug("Self sign-up confirmation code is expired.", e);
                }
                throw new UserPortalUIException(e.getErrorCode(), "Error occurred during self sign-up user " +
                                                                 "confirmation.");
            } else if (ErrorCodes.INVALID_CODE.getCode().equals(e.getErrorCode())) {
                if (log.isDebugEnabled()) {
                    log.debug("Self sign-up confirmation code is invalid.", e);
                }
                throw new UserPortalUIException(e.getErrorCode(), "Error occurred during self sign-up user " +
                                                                  "confirmation.");
            }

            if (log.isDebugEnabled()) {
                log.debug("Error occurred during self sign-up user confirmation.", e);
            }

            throw new UserPortalUIException("Error occurred during self sign-up user confirmation.");
        } catch (IdentityRecoveryException e) {
            log.error("Server error occurred during self sign-up user confirmation.", e);
            throw new UserPortalUIException("Error occurred during self sign-up user confirmation.");

        }
    }

    @Override
    public NotificationResponseBean resendConfirmationCode(Map<String, String> userClaims, String domainName,
                                                       Map<String, String> properties) throws UserPortalUIException {

        List<Claim> claims = userClaims.entrySet()
                                              .stream()
                                              .map(claim -> new Claim(IdentityMgtConstants.CLAIM_ROOT_DIALECT,
                                                                      claim.getKey(), claim.getValue()))
                                              .collect(Collectors.toList());

        return resendConfirmationCode(claims.get(0), domainName, properties);

    }

    private NotificationResponseBean resendConfirmationCode(Claim claim, String domainName, Map<String, String>
            properties) throws UserPortalUIException {

        Property[] props = properties.entrySet().stream()
                                     .map(x -> new Property(x.getKey(), x.getValue()))
                                     .toArray(Property[]::new);

        try {
            return userSelfSignUpManager.resendConfirmationCode(claim, domainName, props);
        } catch (IdentityRecoveryException e) {
            String message = "Error occurred while resending confirmation email.";
            log.error(message, e);
            throw new UserPortalUIException(message);
        }

    }
}
