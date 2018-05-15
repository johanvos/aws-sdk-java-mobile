/*
  * Copyright 2017-2017 Amazon.com, Inc. or its affiliates.
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

import com.amazonaws.ClientConfiguration;
import com.amazonaws.SDKGlobalConfiguration;

import com.amazonaws.auth.AWSBasicCognitoIdentityProvider;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.CognitoCachingCredentialsProvider;

import com.amazonaws.mobile.auth.core.signin.AuthException;
import com.amazonaws.mobile.auth.core.signin.CognitoAuthException;
import com.amazonaws.mobile.auth.core.signin.ProviderAuthException;
import com.amazonaws.mobile.auth.core.signin.SignInManager;
import com.amazonaws.mobile.auth.core.signin.SignInProvider;
import com.amazonaws.mobile.auth.core.signin.SignInProviderResultHandler;
import com.amazonaws.mobile.config.AWSConfiguration;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.gluonhq.charm.down.Services;
import com.gluonhq.charm.down.plugins.SettingsService;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.application.Platform;


/**
 * The identity manager keeps track of the current sign-in provider and is responsible
 * for caching credentials.
 * 
 * <pre>
 * // Create IdentityManager and set it as the default instance.
 * IdentityManager idm = new IdentityManager(new AWSConfiguration(getApplicationContext()));
 * IdentityManager.setDefaultIdentityManager(idm);
 * 
 * // Use IdentityManager to retrieve the {@link com.amazonaws.auth.CognitoCachingCredentialsProvider}
 * // object.
 * IdentityManager.getDefaultIdentityManager().getUnderlyingProvider();
 * 
 * </pre>
 */
public class IdentityManager {

    private static final Logger LOG = Logger.getLogger(IdentityManager.class.getName());
    
    /** Holder for the credentials provider, allowing the underlying provider to be swapped when necessary. */
    private class AWSCredentialsProviderHolder implements AWSCredentialsProvider {

        /** Reference to the credentials provider. */
        private volatile CognitoCachingCredentialsProvider underlyingProvider;

        @Override
        public AWSCredentials getCredentials() {
            return underlyingProvider.getCredentials();
        }

        @Override
        public void refresh() {
            underlyingProvider.refresh();
        }

        private CognitoCachingCredentialsProvider getUnderlyingProvider() {
            return underlyingProvider;
        }

        private void setUnderlyingProvider(final CognitoCachingCredentialsProvider underlyingProvider) {
            // if the current underlyingProvider is not null
            this.underlyingProvider = underlyingProvider;
        }
    }

    /** AWS Configuration json file */
    private static final String AWS_CONFIGURATION_FILE = "awsconfiguration.json";

    /** Holder for the credentials provider, allowing the underlying provider to be swapped when necessary. */
    private final AWSCredentialsProviderHolder credentialsProviderHolder;

    /** Configuration for the mobile helper. */
    private AWSConfiguration awsConfiguration;

    /* SDK Client configuration. */
    private final ClientConfiguration clientConfiguration;

    /** Executor service for obtaining credentials in a background thread. */
    private final ExecutorService executorService = Executors.newFixedThreadPool(4);

    /** Timeout CountdownLatch for doStartupAuth(). */
    private final CountDownLatch startupAuthTimeoutLatch = new CountDownLatch(1);

    /** Keep track of the registered sign-in providers. */
    private final List<Class<? extends SignInProvider>> signInProviderClasses 
        = new LinkedList<Class<? extends SignInProvider>>();

    /** Current provider beingIdentityProviderType used to obtain a Cognito access token. */
    private volatile IdentityProvider currentIdentityProvider = null;

    /** Results adapter for adapting results that came from logging in with a provider. */
    private SignInProviderResultAdapter resultsAdapter;

    /** Keep track of the currently registered SignInStateChangeListeners. */
    private final HashSet<SignInStateChangeListener> signInStateChangeListeners 
        = new HashSet<SignInStateChangeListener>();

    /** Reference to the default identity manager */
    private static IdentityManager defaultIdentityManager = null;

    /** 
     * SharedPreferences key name used to store the short-lived AWS Credentials
     * by the CognitoCachingCredentialsProvider.
     */
    private static final String SHARED_PREF_NAME = "com.amazonaws.android.auth";
    
    /** 
     * SharedPreferences key name used to store the expiration date for the 
     * short-lived AWS Credentials.
     */
    private static final String EXPIRATION_KEY = "expirationDate";

    /**
     * Custom Amazon Cognito Identity Provider to handle refreshing the sign-in provider's token.
     */
    private class AWSRefreshingCognitoIdentityProvider extends AWSBasicCognitoIdentityProvider {

        /** Log tag. */
        private final String LOG_TAG = AWSRefreshingCognitoIdentityProvider.class.getSimpleName();

        public AWSRefreshingCognitoIdentityProvider(final String accountId,
                                                    final String identityPoolId,
                                                    final ClientConfiguration clientConfiguration,
                                                    final Regions regions) {
            super(accountId, identityPoolId, clientConfiguration);
            // Force refreshing Identity provider to use same region as 
            // CognitoCachingCredentialsProvider
            this.cib.setRegion(Region.getRegion(regions));
        }

        @Override
        public String refresh() {

            if (currentIdentityProvider != null) {
                LOG.log(Level.FINE, "Storing the Refresh token in the loginsMap.");
                final String newToken = currentIdentityProvider.refreshToken();
                getLogins().put(currentIdentityProvider.getCognitoLoginKey(), newToken);
            }
            return super.refresh();
        }
    }

    /**
     * Constructor that takes in the application context.
     * 
     * @param context the application context.
     */
    public IdentityManager() {
        this.awsConfiguration = null;
        this.clientConfiguration = null;
        this.credentialsProviderHolder = null;
    }

    /**
     * Constructor. 
     * Initializes with the application context and the AWSConfiguration passed in.
     * Creates a default ClientConfiguration with the user agent from AWSConfiguration.
     *
     * @param awsConfiguration the aws configuration.
     */
    public IdentityManager(final AWSConfiguration awsConfiguration) {
        this.awsConfiguration = awsConfiguration;
        this.clientConfiguration = new ClientConfiguration().withUserAgent(awsConfiguration.getUserAgent());
        this.credentialsProviderHolder = new AWSCredentialsProviderHolder();
        createCredentialsProvider(this.clientConfiguration);
    }

    /**
     * Constructor.
     * Initializes with the application context, the AWSConfiguration
     * and the ClientConfiguration passed in.
     * Read the UserAgent from AWSConfiguration and set in ClientConfiguration.
     *
     * @param awsConfiguration the aws configuration.
     * @param clientConfiguration the client configuration options such as retries and timeouts.
     */
    public IdentityManager(final AWSConfiguration awsConfiguration,
                           final ClientConfiguration clientConfiguration) {
        this.awsConfiguration = awsConfiguration;
        this.clientConfiguration = clientConfiguration;

        final String userAgent = this.awsConfiguration.getUserAgent();
        String currentUserAgent = this.clientConfiguration.getUserAgent();
        currentUserAgent = currentUserAgent != null ? currentUserAgent : "";
 
        if (userAgent != null && userAgent != currentUserAgent) {
            this.clientConfiguration.setUserAgent(currentUserAgent.trim() + " " + userAgent);
        }

        this.credentialsProviderHolder = new AWSCredentialsProviderHolder();
        createCredentialsProvider(this.clientConfiguration);
    }

    /**
     * Constructor.
     * Initializes with the activity context, application's credentials provider
     * that provides the identity and the client configuration.
     *
     * @param credentialsProvider
     * @param clientConfiguration the client configuration options such as retries and timeouts.
     */
    public IdentityManager(final CognitoCachingCredentialsProvider credentialsProvider,
                           final ClientConfiguration clientConfiguration) {
        this.clientConfiguration = clientConfiguration;
        this.credentialsProviderHolder = new AWSCredentialsProviderHolder();
        credentialsProviderHolder.setUnderlyingProvider(credentialsProvider);
    }


    /**
     * Return the default instance of the IdentityManager
     *
     * @return defaultIdentityManager The default IdentityManager object
     */
    public static IdentityManager getDefaultIdentityManager() {
        return defaultIdentityManager;
    }

    /**
     * Set the IdentityManager object passed in as the default instance
     *
     * @param identityManager The IdentityManager object to be set as the default
     */
    public static void setDefaultIdentityManager(IdentityManager identityManager) {
        defaultIdentityManager = null;
        defaultIdentityManager = identityManager;
    }

    /**
     * Retrieve the AWSConfiguration object that represents the `awsconfiguration.json`.
     *
     * @return AWSConfiguration Return the reference to the AWSConfiguration object
     */
    public AWSConfiguration getConfiguration() {
        return this.awsConfiguration;
    }

    /**
     * Set the AWSConfiguration.
     * @param configuration
     */
    public void setConfiguration(AWSConfiguration configuration) {
        this.awsConfiguration = configuration;
    }

    /**
     * Check if the short-lived AWS Credentials are expired.
     *
     * @return true if the cached short-lived AWS credentials are expired, otherwise false.
     */
    public boolean areCredentialsExpired() {

        final Date credentialsExpirationDate =
            credentialsProviderHolder.getUnderlyingProvider().getSessionCredentitalsExpiration();

        if (credentialsExpirationDate == null) {
            LOG.log(Level.FINE, "Credentials are EXPIRED.");
            return true;
        }

        long currentTime = System.currentTimeMillis() -
                (long)(SDKGlobalConfiguration.getGlobalTimeOffset() * 1000);

        final boolean credsAreExpired =
                (credentialsExpirationDate.getTime() - currentTime) < 0;

        LOG.log(Level.FINE, "Credentials are " + (credsAreExpired ? "EXPIRED." : "OK"));

        return credsAreExpired;
    }

    /**
     * Retrieve the reference to AWSCredentialsProvider object.
     *
     * @return the holder to the CognitoCachingCredentialsProvider.
     */
    public AWSCredentialsProvider getCredentialsProvider() {
        return this.credentialsProviderHolder;
    }

    /**
     * Retrieve the reference to CognitoCachingCredentialsProvider object.
     *
     * @return the Cognito Caching Credentials Provider
     */
    public CognitoCachingCredentialsProvider getUnderlyingProvider() {
        return this.credentialsProviderHolder.getUnderlyingProvider();
    }

    /**
     * Gets the cached unique identifier for the user.
     *
     * @return the cached unique identifier for the user.
     */
    public String getCachedUserID() {
        return credentialsProviderHolder.getUnderlyingProvider().getCachedIdentityId();
    }

    /**
     * Gets the user's unique identifier. This method can be called from
     * any thread.
     *
     * @param handler handles the unique identifier for the user
     */
    public void getUserID(final IdentityHandler handler) {

        executorService.submit(new Runnable() {
            Exception exception = null;

            @Override
            public void run() {
                String identityId = null;

                try {
                    // Retrieve the user identity on the background thread.
                    identityId = credentialsProviderHolder.getUnderlyingProvider().getIdentityId();
                } catch (final Exception exception) {
                    this.exception = exception;
                    LOG.log(Level.WARNING, exception.getMessage(), exception);
                } finally {
                    final String result = identityId;
                    LOG.log(Level.FINE, "Got Amazon Cognito Federated Identity ID: " + identityId);

                    if (handler != null) {
                        Platform.runLater(new Runnable() {
                            @Override
                            public void run() {
                                if (exception != null) {
                                    handler.handleError(exception);
                                } else {
                                    handler.onIdentityId(result);
                                }
                            }
                        });
                    }
                }
            }
        });
    }

    /**
     * The adapter to handle results that come back from Cognito as well as handle the result from
     * any login providers.
     */
    private class SignInProviderResultAdapter implements SignInProviderResultHandler {
        final private SignInProviderResultHandler handler;

        private SignInProviderResultAdapter(final SignInProviderResultHandler handler) {
            this.handler = handler;
        }

        @Override
        public void onSuccess(final IdentityProvider provider) {
            LOG.log(Level.FINE,
                    String.format("SignInProviderResultAdapter.onSuccess(): %s provider sign-in succeeded.",
                            provider.getDisplayName()));
            // Update Cognito login with the token.
            federateWithProvider(provider);
        }

        private void onCognitoSuccess() {
            LOG.log(Level.FINE, "SignInProviderResultAdapter.onCognitoSuccess()");
            handler.onSuccess(currentIdentityProvider);
        }

        private void onCognitoError(final Exception ex) {
            LOG.log(Level.FINE, "SignInProviderResultAdapter.onCognitoError()", ex);
            final IdentityProvider provider = currentIdentityProvider;
            // Sign out of parent provider. This clears the currentIdentityProvider.
            IdentityManager.this.signOut();
            handler.onError(provider, new CognitoAuthException(provider, ex));
        }

        @Override
        public void onCancel(final IdentityProvider provider) {
            LOG.log(Level.FINE, String.format(
                "SignInProviderResultAdapter.onCancel(): %s provider sign-in canceled.",
                provider.getDisplayName()));
            handler.onCancel(provider);
        }

        @Override
        public void onError(final IdentityProvider provider, final Exception ex) {
            LOG.log(Level.WARNING,
                String.format("SignInProviderResultAdapter.onError(): %s provider error. %s",
                              provider.getDisplayName(), ex.getMessage()), ex);
            handler.onError(provider, new ProviderAuthException(provider, ex));
        }
    }

    /**
     * Add a listener to receive callbacks when sign-in or sign-out occur.  The listener
     * methods will always be called on a background thread.
     *
     * @param listener the sign-in state change listener.
     */
    public void addSignInStateChangeListener(final SignInStateChangeListener listener) {
        synchronized (signInStateChangeListeners) {
            signInStateChangeListeners.add(listener);
        }
    }

    /**
     * Remove a listener from receiving callbacks when sign-in or sign-out occur.
     *
     * @param listener the sign-in state change listener.
     */
    public void removeSignInStateChangeListener(final SignInStateChangeListener listener) {
        synchronized (signInStateChangeListeners) {
            signInStateChangeListeners.remove(listener);
        }
    }

    /**
     * Call getResultsAdapter to get the IdentityManager's handler that adapts results before
     * sending them back to the handler set by {@link #setProviderResultsHandler(SignInProviderResultHandler)}
     *
     * @return the Identity Manager's results adapter.
     */
    public SignInProviderResultAdapter getResultsAdapter() {
        return resultsAdapter;
    }

    /**
     * Sign out of the current identity provider, and clear Cognito credentials.
     * Note: This call does not attempt to obtain un-auth credentials. To obtain an unauthenticated
     * anonymous (guest) identity, call {@link #getUserID(IdentityHandler)}.
     */
    public void signOut() {
        LOG.log(Level.FINE, "Signing out...");

        if (currentIdentityProvider != null) {
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    currentIdentityProvider.signOut();
                    credentialsProviderHolder.getUnderlyingProvider().clear();
                    currentIdentityProvider = null;

                    // Notify state change listeners of sign out.
                    synchronized (signInStateChangeListeners) {
                        for (final SignInStateChangeListener listener : signInStateChangeListeners) {
                            listener.onUserSignedOut();
                        }
                    }
                }
            });
        }
    }

    /**
     * Set the loginMap of the CognitoCachingCredentialsProvider
     * and invoke refresh. This retrieves the AWS Identity and the
     * short-lived AWS Credentials to access other AWS resources.
     * 
     * @param loginMap the map with a key-value pair of 
     *                 sign-in provider key and the token 
     */
    private void refreshCredentialWithLogins(final Map<String, String> loginMap) {
      
        final CognitoCachingCredentialsProvider credentialsProvider =
            credentialsProviderHolder.getUnderlyingProvider();
        credentialsProvider.clear();
        credentialsProvider.withLogins(loginMap);
      
        // Calling refresh is equivalent to calling getIdentityId() + getCredentials().
        LOG.log(Level.FINE, "refresh credentials");
        credentialsProvider.refresh();

        // Set the expiration key of the Credentials Provider to 8 minutes, 30 seconds.
        Services.get(SettingsService.class).ifPresent(new Consumer<SettingsService>() {
            @Override
            public void accept(SettingsService settings) {
                settings.store(credentialsProvider.getIdentityPoolId() + "." + EXPIRATION_KEY,
                           Long.toString(System.currentTimeMillis() + (510 * 1000)));
                
            }
        });
    }

    /**
     * Set the results handler that will be used for results when calling federateWithProvider.
     *
     * @param signInProviderResultHandler the results handler.
     */
    public void setProviderResultsHandler(final SignInProviderResultHandler signInProviderResultHandler) {
        if (signInProviderResultHandler == null) {
            throw new IllegalArgumentException("signInProviderResultHandler cannot be null.");
        }
        this.resultsAdapter = new SignInProviderResultAdapter(signInProviderResultHandler);
    }

    /**
     * Fetch the token from the SignIn provider and insert into the loginMap
     * and then invoke {@link #refreshCredentialWithLogins(Map)} to set the
     * loginsMap with the CredentialsProvider object in-order to federate 
     * the token with Amazon Cognito Federated Identities.
     *
     * @param provider A sign-in provider.
     */
    public void federateWithProvider(final IdentityProvider provider) {
        LOG.log(Level.FINE, "federate with provider: Populate loginsMap with token.");
        final Map<String, String> loginMap = new HashMap<String, String>();
        loginMap.put(provider.getCognitoLoginKey(), provider.getToken());
        currentIdentityProvider = provider;

        executorService.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    refreshCredentialWithLogins(loginMap);
                } catch (Exception ex) {
                    resultsAdapter.onCognitoError(ex);
                    return;
                }

                resultsAdapter.onCognitoSuccess();

                // Notify state change listeners of sign out.
                synchronized (signInStateChangeListeners) {
                    for (final SignInStateChangeListener listener : signInStateChangeListeners) {
                        listener.onUserSignedIn();
                    }
                }
            }
        });
    }

    /**
     * Gets the current provider.
     *
     * @return current provider or null if not signed-in
     */
    public IdentityProvider getCurrentIdentityProvider() {
        return currentIdentityProvider;
    }

    /**
     * Add a supported identity provider to your app. 
     * The provider will be presented as option to sign in to your app.
     *
     * @param providerClass the provider class for the identity provider.
     */
    public void addSignInProvider(final Class<? extends SignInProvider> providerClass) {
        signInProviderClasses.add(providerClass);
    }

    /**
     * Gets the list of SignInProvider classes
     *
     * @return list of the signInProvider classes
     */
    public Collection<Class<? extends SignInProvider>> getSignInProviderClasses() {
        return signInProviderClasses;
    }

    /**
     * Check if user is signed in.
     *
     * @return true if Cognito credentials have been obtained with at least one provider.
     */
    public boolean isUserSignedIn() {
        final Map<String, String> logins = credentialsProviderHolder.getUnderlyingProvider().getLogins();
        if (logins == null || logins.size() == 0)
            return false;
        return true;
    }

    /**
     * Invoke the onComplete method on the {@link StartupAuthResultHandler}
     * callback object.
     * 
     * @param callingActivity the activity context
     * @param startupAuthResultHandler the callback object
     * @param ex the exception if raised during the resume session
     */
    private void completeHandler(final StartupAuthResultHandler startupAuthResultHandler,
                                 final AuthException ex) {
        runAfterStartupAuthDelay(new Runnable() {
            @Override
            public void run() {
                startupAuthResultHandler.onComplete(new StartupAuthResult(IdentityManager.this,
                    new StartupAuthErrorDetails(ex, null)));
            }
        });
    }

    /**
     * Invoke the completeHandler after the resume session timeout
     * by running the Runnable on th UI thread. This method is 
     * currently being called from a background thread.
     *
     * @param runnable runnable to run after the splash timeout expires.
     */
    private void runAfterStartupAuthDelay(final Runnable runnable) {
        executorService.submit(new Runnable() {
            public void run() {
                // Wait for the startupAuthTimeoutLatch to go to zero.
                try {
                    startupAuthTimeoutLatch.await();
                } catch (InterruptedException e) {
                    LOG.log(Level.FINE, "Interrupted while waiting for startup auth minimum delay.");
                }

                // Notify user by invoking the callback on the UI thread
                Platform.runLater(runnable);
            }
        });
    }

    /**
     * This should be called from your app's activity upon start-up. If the user was previously
     * signed-in, this will attempt to refresh their identity using the previously signed-in provider.
     * If the user was not previously signed in or their identity could not be refreshed with the
     * previously signed-in provider, it will attempt to obtain an unauthenticated identity.
     *
     * @param startupAuthResultHandler a handler for returning results.
     * @param minimumDelay the minimum delay to wait before returning the sign-in result.
     */
    public void resumeSession(final StartupAuthResultHandler startupAuthResultHandler,
                              final long minimumDelay) {

        LOG.log(Level.FINE, "Resume Session called.");
        
        executorService.submit(new Runnable() {
            public void run() {
                LOG.log(Level.FINE, "Looking for a previously signed-in session.");
                final SignInManager signInManager = SignInManager.getInstance();
                
                final SignInProvider signInProvider = signInManager.getPreviouslySignedInProvider();

                // if the user was previously signed-in with an sign-in provider and
                // we are able to verify with the sign-in provider.
                if (signInProvider != null) {
                    LOG.log(Level.FINE, "Refreshing credentials with sign-in provider "
                        + signInProvider.getDisplayName());
                    // TODO
                    throw new UnsupportedOperationException("Not supported yet");
                    
                    /*
                    // Use the token from the previously signed-in session to
                    // get a AWS Identity using Cognito Federated Identities
                    // The AWS Identity will be wrapped into the CredentialsProvider
                    // which will contain short-lived AWS Credentials to access
                    // AWS resources.             
                    signInManager.refreshCredentialsWithProvider(signInProvider,
                            new SignInProviderResultHandler() {

                                @Override
                                public void onSuccess(final IdentityProvider provider) {
                                    LOG.log(Level.FINE, "Successfully got AWS Credentials.");
        
                                    runAfterStartupAuthDelay(new Runnable() {
                                        @Override
                                        public void run() {
                                            startupAuthResultHandler.onComplete(new StartupAuthResult(IdentityManager.this, null));
                                        }
                                    });
                                }
        
                                @Override
                                public void onCancel(final IdentityProvider provider) {
                                    LOG.log(Level.SEVERE, "Cancel can't happen when handling a previously signed-in user.");
                                }
        
                                @Override
                                public void onError(final IdentityProvider provider, final Exception ex) {
                                    LOG.log(Level.WARNING,
                                            String.format("Federate with Cognito with %s Sign-in provider failed. Error: %s",
                                                    provider.getDisplayName(), ex.getMessage()), ex);
        
                                    if (ex instanceof AuthException) {
                                        completeHandler(startupAuthResultHandler,
                                                (AuthException) ex);
                                    } else {
                                        completeHandler(startupAuthResultHandler,
                                                new AuthException(provider, ex));
                                    }
                                }
                            });
                    */
                } else {
                    // No previously signed-in provider found. No session to resume.
                    // Notify the user by executing the callback handler.
                    completeHandler(startupAuthResultHandler, null);
                }

                if (minimumDelay > 0) {
                    // Wait for the expiration timeout.
                    try {
                        Thread.sleep(minimumDelay);
                    } catch (final InterruptedException ex) {
                        LOG.log(Level.INFO, "Interrupted while waiting for resume session timeout.");
                    }
                }

                // Expire the resume session timeout.
                startupAuthTimeoutLatch.countDown();
            }
        });
    }

    /**
     * This should be called from your app's splash activity upon start-up. If the user was previously
     * signed in, this will attempt to refresh their identity using the previously sign-ed in provider.
     * If the user was not previously signed in or their identity could not be refreshed with the
     * previously signed in provider and sign-in is optional, it will attempt to obtain an unauthenticated (guest)
     * identity.
     *
     * @param startupAuthResultHandler a handler for returning results.
     */
    public void resumeSession(final StartupAuthResultHandler startupAuthResultHandler) {
        resumeSession(startupAuthResultHandler, 0);
    }

    /**
     * This should be called from your app's splash activity upon start-up. If the user was previously
     * signed in, this will attempt to refresh their identity using the previously sign-ed in provider.
     * If the user was not previously signed in or their identity could not be refreshed with the
     * previously signed in provider and sign-in is optional, it will attempt to obtain an unauthenticated (guest)
     * identity.
     *
     * @param startupAuthResultHandler a handler for returning results.
     * @deprecated Please use {@link #resumeSession(Activity, StartupAuthResultHandler)} method instead.
     */
    @Deprecated
    public void doStartupAuth(final StartupAuthResultHandler startupAuthResultHandler) {
        resumeSession(startupAuthResultHandler, 0);
    }

    /**
     * This should be called from your app's splash activity upon start-up. If the user was previously
     * signed in, this will attempt to refresh their identity using the previously sign-ed in provider.
     * If the user was not previously signed in or their identity could not be refreshed with the
     * previously signed in provider and sign-in is optional, it will attempt to obtain an unauthenticated (guest)
     * identity.
     *
     * @param startupAuthResultHandler a handler for returning results.
     * @param minimumDelay
     * @deprecated Please use {@link #resumeSession(Activity, StartupAuthResultHandler, long)} method instead.
     */
    @Deprecated
    public void doStartupAuth(final StartupAuthResultHandler startupAuthResultHandler,
                              final long minimumDelay) {
        resumeSession(startupAuthResultHandler, minimumDelay);
    }

    /**
     * Call this to ignore waiting for the remaining timeout delay.
     */
    public void expireSignInTimeout() {
        startupAuthTimeoutLatch.countDown();
    }

    /**
     * Call setUpToAuthenticate to initiate sign-in with a provider.
     *
     * Note: This should not be called when already signed in with a provider.
     *
     * @param signInResultHandler the results handler.
     * @deprecated Please use {@link #login(Context, SignInResultHandler)} method instead.
     */
    @Deprecated
    public void setUpToAuthenticate(final SignInResultHandler signInResultHandler) {
        this.login(signInResultHandler);
    }

    /**
     * Call login to initiate sign-in with a provider.
     *
     * Note: This should not be called when already signed in with a provider.
     *
     * @param signInResultHandler the results handler.
     */
    public void login(final SignInResultHandler signInResultHandler) {
        // Start the sign-in activity. 
        // We do not finish the calling activity allowing the user to navigate back.
        // TODO
        throw new UnsupportedOperationException("Not supported yet");
//        try {
//            SignInManager
//                .getInstance()
//                .setResultHandler(signInResultHandler);
//        } catch (final Exception exception) {
//            LOG.log(Level.WARNING, "Error in instantiating SignInManager. " +
//                           "Check the context and completion handler.", exception);
//        }
    }

    /**
     *   The CognitoCachingCredentialProvider loads cached credentials when it is
     *   instantiated, however, it does not reload the login map, which must be reloaded
     *   in order to refresh the credentials.  Therefore, currently cached credentials are
     *   only useful for unauthenticated users.
     */
    private void createCredentialsProvider(final ClientConfiguration clientConfiguration) {

        try {
            LOG.log(Level.FINE, "Creating the Cognito Caching Credentials Provider "
                    + "with a refreshing Cognito Identity Provider.");
            
            final String region = getCognitoIdentityRegion();
            final Regions cognitoIdentityRegion = Regions.fromName(region);
            
            final AWSRefreshingCognitoIdentityProvider refreshingCredentialsProvider =
                    new AWSRefreshingCognitoIdentityProvider(null, getCognitoIdentityPoolId(),
                            clientConfiguration, cognitoIdentityRegion);
            
            credentialsProviderHolder.setUnderlyingProvider(
                    new CognitoCachingCredentialsProvider(refreshingCredentialsProvider,
                            cognitoIdentityRegion, clientConfiguration));
        } catch (Throwable ex) {
            LOG.log(Level.SEVERE, "Error createCredentialsProvider", ex);
        }
    }

    /**
     * Retrieve the Cognito IdentityPooldId from CognitoIdentity -> PoolId key
     *
     * @return PoolId
     * @throws IllegalArgumentException
     */
    private String getCognitoIdentityPoolId() throws IllegalArgumentException {
        try {
            return this.awsConfiguration
                .optJsonObject("CredentialsProvider")
                .getJSONObject("CognitoIdentity")
                .getJSONObject(this.awsConfiguration.getConfiguration())
                .getString("PoolId");
        } catch (Exception exception) {
            throw new IllegalArgumentException("Cannot access Cognito IdentityPoolId from the "
                    + AWS_CONFIGURATION_FILE + " file.", exception);
        }
    }

    /**
     * Retrieve the Cognito Region from CognitoIdentity -> Region key
     *
     * @return CognitoIdentity Region
     * @throws IllegalArgumentException
     */
    private String getCognitoIdentityRegion() throws IllegalArgumentException {
        try {
            return this.awsConfiguration
                  .optJsonObject("CredentialsProvider")
                  .getJSONObject("CognitoIdentity")
                  .getJSONObject(this.awsConfiguration.getConfiguration())
                  .getString("Region");
        } catch (Exception exception) {
            throw new IllegalArgumentException("Cannot find the Cognito Region from the "
                    + AWS_CONFIGURATION_FILE + " file.", exception);
        }
    }
}
