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

import org.wso2.carbon.identity.recovery.bean.NotificationResponseBean;
import org.wso2.is.portal.user.client.api.exception.UserPortalUIException;

import java.util.Map;

/**
 * Self sign-up client service.
 */
public interface SelfSignUpClientService {

    NotificationResponseBean registerUser(Map<String, String> userClaims, Map<String, String> credentials, String
            domain, Map<String, String> properties) throws UserPortalUIException;

    void confirmUserSelfSignUp(String code) throws UserPortalUIException;

    NotificationResponseBean resendConfirmationCode(Map<String, String> userClaims, String domainName, Map<String,
            String> properties) throws UserPortalUIException;

    NotificationResponseBean resendConfirmationCode(String uniqueUserId, Map<String, String> properties) throws
            UserPortalUIException;
}
