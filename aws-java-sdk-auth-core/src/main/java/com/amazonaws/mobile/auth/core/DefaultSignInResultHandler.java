/*
  * Copyright 2013-2017 Amazon.com, Inc. or its affiliates.
  * All Rights Reserved.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *     http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

package com.amazonaws.mobile.auth.core;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A default base class easing the work required for implementing the SignInResultHandler for
 * {@link IdentityManager#login(Context, SignInResultHandler)} by providing default
 * behavior in the case that the user cancels signing in or encounters an error. The default for
 * canceling is to toast that sign-in was canceled. The default for a sign-in error is to show
 * an alert dialog specifying the error message.
 */
public abstract class DefaultSignInResultHandler implements SignInResultHandler {

    private static final Logger LOG = Logger.getLogger(DefaultSignInResultHandler.class.getName());
    
    /**
     * User cancelled signing in with a provider on the sign-in activity.
     * Note: The user is still on the sign-in activity when this call is made.
     * @param provider the provider the user canceled with.
     */
    @Override
    public void onIntermediateProviderCancel(IdentityProvider provider) {
        LOG.log(Level.FINE, String.format("%s Sign-In flow is canceled", provider.getDisplayName()));
    }

    /**
     * User encountered an error when attempting to sign-in with a provider.
     * Note: The user is still on the sign-in activity when this call is made.
     * @param provider the provider the user attempted to sign-in with that encountered an error.
     * @param ex the exception that occurred.
     */
    @Override
    public void onIntermediateProviderError(IdentityProvider provider, Exception ex) {
        // TODO: Get i18n error
        final String failureFormatString = "sign_in_failure_message_format";
        LOG.log(Level.WARNING, String.format(failureFormatString, provider.getDisplayName(), ex.getMessage()), ex);
    }
}
