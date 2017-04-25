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

var USERNAME_CLAIM = "http://wso2.org/claims/username";

function confirmSignUp(confirmationCode) {
    try {
        var selfSignUpResult = callOSGiService("org.wso2.is.portal.user.client.api.SelfSignUpClientService",
                                                           "confirmUserSelfSignUp", [confirmationCode]);
        return {};
    } catch (e) {
        var cause = e.getCause();
        var error = cause.getTargetException();
        Log.error(e);
        return {errorMessage: 'signup.error.registration', errorCode: error.getErrorCode()};
    }
}

function resendConfirmationByID(userId, propertyMap) {

    try {
        var selfSignUpResult = callOSGiService("org.wso2.is.portal.user.client.api.SelfSignUpClientService",
                                                           "resendConfirmationCode", [userId, propertyMap]);
        return {};
    } catch (e) {
        Log.error("Error while user sign-up.", e);
        return {errorMessage: 'error.resend.confirmation', errorCode: e.getCode()};
    }
}

function resendConfirmation(username, domain, propertyMap) {

    try {
        var selfSignUpResult = callOSGiService("org.wso2.is.portal.user.client.api.SelfSignUpClientService",
                                                           "resendConfirmationCode", [username, domain, propertyMap]);
        return {};
    } catch (e) {
        return {errorMessage: 'error.resend.confirmation'};
    }
}

function onGet(env) {

    var confirmationCode =  env.request.queryParams["confirmation"];
    var userId = env.request.queryParams["id"];
    var callback = env.request.queryParams["callback"];
    var confirmationResponse;

    if (confirmationCode) {
         confirmationCode = confirmSignUp(confirmationCode);
    } else {

    }

    if (confirmationResponse.errorCode && ("18001" === confirmationResponse.errorCode ||
                                           "18002" === confirmationResponse.errorCode)) {
        if (!userId) {
            return {errorMessage: "user.confirmation.error", errorDescription: "confirmation.invalid.description"};

        } else {

            var message;
            var description;
            var result = {id: userId, callback: callback, isReconfirmationRequired: true};
            var notificationInternallyManaged = true;

            if ("18001" === confirmationResponse.errorCode) {

                result['message'] = "confirmation.invalid";
                result['description'] = "confirmation.invalid.description";
            } else {

                result['resend'] = true;
                result['message'] = "confirmation.expired";

                if (notificationInternallyManaged) {
                    result['description'] = "confirmation.expired.resend.description";
                } else {
                    result['description'] = "confirmation.expired.description";
                }
            }

            return result;
        }
    } else if (confirmationResponse.errorMessage) {
        return {errorMessage: "user.confirmation.error", errorDescription: "user.confirmation.error.description"};
    }

    return {isConfirmationCodeValid: true};
}

function onPost(env) {

    var userId = env.request.formParams["uid"];
    var callback = env.request.formParams["callback"];
    var username = env.request.formParams["unconfirmed-user"];
    var domain = env.request.formParams["unconfirmed-domain"];
    var propertyMap = {};
    var resendConfirmationResult;

    if (callback) {
        propertyMap["callback"] = callback;
    } else {

        var protocol = env.request.isSecure() ? "https" : "http";
        callback = protocol + "//" + env.request.headers["Host"] + env.contextPath + env.config['loginRedirectUri'];

        Log.debug("Missing callback URL in the request. Callback is set to default: " + callback);
    }

    if (userId) {

        resendConfirmationResult = resendConfirmationByID(userId, propertyMap);

        if (resendConfirmationResult.errorMessage) {
            return {errorMessage: "failed.confirmation.mail.resend", errorDescription: "resend.failed.description"};
        } else {
            return {hasConfirmationCodeSent: true, callback: callback};
        }
    } else if (username) {

        var userClaims = {};
        userClaims[USERNAME_CLAIM] = username;

        resendConfirmationResult = resendConfirmation(userClaims, domain, propertyMap);

        if (resendConfirmationResult.errorMessage) {
            return {errorMessage: "failed.confirmation.mail.resend", errorDescription: "resend.failed.description"};
        } else {
            return {hasConfirmationCodeSent: true, callback: callback};
        }

    } else {
        Log.debug("Cannot send confirmation email. Missing user info.");
        return {errorMessage: "failed.confirmation.mail.resend", errorDescription: "resend.failed.description"};
    }

}