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

package com.amazonaws.mobile.client;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.mobile.auth.core.signin.SignInProvider;
//import com.amazonaws.mobile.auth.facebook.FacebookButton;
//import com.amazonaws.mobile.auth.facebook.FacebookSignInProvider;
//import com.amazonaws.mobile.auth.google.GoogleButton;
//import com.amazonaws.mobile.auth.google.GoogleSignInProvider;
//import com.amazonaws.mobile.auth.userpools.CognitoUserPoolsSignInProvider;;
import com.amazonaws.mobile.config.AWSConfiguration;
import com.amazonaws.mobile.config.AWSConfigurable;

import com.amazonaws.mobile.auth.core.IdentityManager;
import com.amazonaws.mobile.auth.core.StartupAuthResult;
import com.amazonaws.mobile.auth.core.StartupAuthResultHandler;
import java.util.LinkedHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * {@code AWSMobileClient} is a high-level SDK client that
 * initilalizes the SDK, fetches Cognito Identity and
 * creates other SDK client instances.
 * 
 * <pre>
 *  To initialize the SDK, invoke the {@link #initialize()}
 *  method:
 * 
 *  AWSMobileClient.getInstance().initialize(this);
 * 
 *  To get a callback when the initalize is successful, invoke the
 *  {@link #initialize(AWSStartupHandler)} method.
 * 
 *  AWSMobileClient.getInstance().initalize(this, new AWSStartupHandler() {
 *      @Override
 *      public void onComplete(AWSStartupResult awsStartupResult) {
 *          // Initialize is complete.
 *      }
 *  });
 * 
 * </pre>
 */
public final class AWSMobileClient {

    private static final Logger LOG = Logger.getLogger(AWSMobileClient.class.getName());

    /** Map of SDK Client Class and object. */
    private final LinkedHashMap<Class<? extends AWSConfigurable>, AWSConfigurable> clientMap;

    /** Singleton instance for AWSMobileClient. */
    private static volatile AWSMobileClient singleton = null;

    /** CredentialsProvider created by the IdentityManager. */
    private AWSCredentialsProvider awsCredentialsProvider;

    /** AWSConfiguration object that represents the `awsconfiguration.json` file. */
    private AWSConfiguration awsConfiguration;

    /** Config of SignInProviders: class and permissions. */
    private SignInProviderConfig[] signInProviderConfig;

    /** Callback for resuming auth session. */
    private StartupAuthResultHandler startupAuthResultHandler;

    /** Callback for initalizing the SDK with AWSMobileClient. */
    private AWSStartupHandler awsStartupHandler;

    /** 
     * Flag to use default config automatically. 
     * Use the default configuration information if TRUE.
     */
    private boolean defaultConfig = true;

    /** Configuration keys for SignInProviders in awsconfiguration.json. */
    private static final String USER_POOLS  = "CognitoUserPool";
    private static final String FACEBOOK    = "FacebookSignIn";
    private static final String GOOGLE      = "GoogleSignIn";
    private static final String PERMISSIONS = "Permissions";
    private static final String GOOGLE_WEBAPP_CONFIG_KEY = "ClientId-WebApp";

    /**
     * Constructor invoked by getInstance.
     *
     * @param context The activity context.
     * @throws AssertionError when this is called with context more than once.
     */
    private AWSMobileClient() {
        if (singleton != null) {
            throw new AssertionError();
        }
        this.clientMap = new LinkedHashMap<Class<? extends AWSConfigurable>, AWSConfigurable>();
    }

    /**
     * This performs basic initialization for connecting
     * to AWS including fetching the Cognito Identity for
     * the user.
     * 
     * @return 
     */
    public InitializeBuilder initialize() {
        this.awsStartupHandler = new AWSStartupHandler() {
            @Override
            public void onComplete(final AWSStartupResult awsStartupResult) {
                 LOG.log(Level.FINE, "AWSMobileClient Initialize succeeded.");
                 LOG.log(Level.INFO, "Welcome to AWS! You are connected successfully.");
            }
        };
        return initialize(this.awsStartupHandler);
    }


    /**
     * This performs basic initialization for connecting
     * to AWS including fetching the Cognito Identity for
     * the user.
     * 
     * @param awsStartupHandler The result for Initialize callback.
     * @return 
     */
    public InitializeBuilder initialize(final AWSStartupHandler awsStartupHandler) {
        this.awsConfiguration = new AWSConfiguration();
        this.signInProviderConfig = null;
        this.startupAuthResultHandler = new StartupAuthResultHandler() {
            @Override
            public void onComplete(final StartupAuthResult startupAuthResult) {
                LOG.log(Level.INFO, "Welcome to AWS! You are connected successfully.");
                if (startupAuthResult.isIdentityIdAvailable()) {
                    LOG.log(Level.INFO, "Identity ID retrieved.");
                }
                awsStartupHandler.onComplete(
                    new AWSStartupResult(IdentityManager.getDefaultIdentityManager()));
            }
        };
        this.awsStartupHandler = awsStartupHandler;
        return new InitializeBuilder();
    }

    /**
     * Initialize the AWSMobileClient with the parameters passed in
     * {@link InitializeBuilder}
     */
    private void initializeWithBuilder(final InitializeBuilder initializeBuilder) {
        if (initializeBuilder.getAwsConfiguration() != null) {
            this.awsConfiguration = initializeBuilder.getAwsConfiguration();
        }

        if (initializeBuilder.getSignInProviderConfig() != null) {
            this.signInProviderConfig = initializeBuilder.getSignInProviderConfig();
        }

        try {
            fetchCognitoIdentity(this.startupAuthResultHandler);
        } catch (final Exception exception) {
            LOG.log(Level.WARNING, "Error in initializing the AWSMobileClient. " +
                            "Check if AWS Cloud Config `awsconfiguration.json` is present in the application.");
        }
    }

    /**
     * Get the AWSConfigurable client if exists, else create one and
     * add it to the clientMap and return.
     *
     * @param clientClass   SDK Client Class that confirms to the AWSConfigurable interface.
     * @return 
     */
    public AWSConfigurable getClient(final Class<? extends AWSConfigurable> clientClass) {

        LOG.log(Level.FINE, "Retrieving the client instance for class: " + clientClass);

        AWSConfigurable client = clientMap.get(clientClass);

        try {
            if (client == null) {
                client = clientClass.newInstance().initialize(this.awsConfiguration);
                clientMap.put(clientClass, client);
                LOG.log(Level.FINE, "Created the new client: " + client.toString());
            }
        } catch (final Exception exception) {
            LOG.log(Level.WARNING, "Error occurred in creating and initializing client. "
                    + "Check the context and the clientClass passed in: " + clientClass, exception);
        }

        return client;
    }

    /**
     * Retrieve the CredentialsProvider.
     * @return the awsCredentialsProvider
     */
    public AWSCredentialsProvider getCredentialsProvider() {
        if (this.awsCredentialsProvider != null) {
            return this.awsCredentialsProvider;
        } else {
            return IdentityManager.getDefaultIdentityManager().getUnderlyingProvider();
        }
    }

    /**
     * Set the CredentialsProvider passed in as the default.
     * @param awsCredentialsProvider The credentials provider object created by the user.
     */
    public void setCredentialsProvider(final AWSCredentialsProvider awsCredentialsProvider) {
        this.awsCredentialsProvider = awsCredentialsProvider;
    }

    /**
     * Retrieve the AWSConfiguration object that represents
     * the awsconfiguration.json file.
     * 
     * @return the AWSConfiguration object
     */
    public AWSConfiguration getConfiguration() {
        return this.awsConfiguration;
    }

    /**
     * Gets the singleton instance of this class.
     * 
     * @return singleton instance
     */
    public static synchronized AWSMobileClient getInstance() {
        if (singleton == null) {
            singleton = new AWSMobileClient();
        }
        return singleton;
    }

    /**
     * Fetch the Cognito Identity for the user.
     * Register the SignProvider with permissions.
     * Resume any previously signed in auth session and fetch the cognito
     * federated identity for the user in order to connect to
     * AWS services.
     *
     * @param context                  The activity context
     * @param startupAuthResultHandler The callback function for resuming session
     */
    private void fetchCognitoIdentity(final StartupAuthResultHandler startupAuthResultHandler) {
        try {
            LOG.log(Level.FINE, "Fetching the Cognito Identity.");
            
            // Create IdentityManager, register the providers and set the permissions.
            final IdentityManager identityManager = new IdentityManager(this.awsConfiguration);
            IdentityManager.setDefaultIdentityManager(identityManager);
            if (this.signInProviderConfig == null) {
                this.registerConfigSignInProviders();
            } else {
                this.registerUserSignInProvidersWithPermissions();
            }
            this.resumeSession(startupAuthResultHandler);
        } catch (final Exception exception) {
            LOG.log(Level.WARNING, "Error occurred in fetching the Cognito Identity "
                    + "and resuming the auth session", exception);
        }
    }

    /**
     * Register the SignInProvider with their permissions 
     * supplied by the user.
     */
    private void registerUserSignInProvidersWithPermissions() {
        LOG.log(Level.FINE, "Using the SignInProviderConfig supplied by the user.");
        final IdentityManager identityManager = IdentityManager.getDefaultIdentityManager();

        for (final SignInProviderConfig config : signInProviderConfig) {
            identityManager.addSignInProvider(config.getSignInProviderClass());
            if (config.getProviderPermissions() != null) {
                // TODO: 
                throw new UnsupportedOperationException("Not supported yet.");
//                if (FacebookSignInProvider.class.isInstance(config.getSignInProviderClass())) {
//                    FacebookSignInProvider.setPermissions(config.getProviderPermissions());
//                }
//                if (GoogleSignInProvider.class.isInstance(config.getSignInProviderClass())) {
//                    GoogleSignInProvider.setPermissions(config.getProviderPermissions());
//                }
            }
        }
    }

    /**
     * Register the SignInProvider and permissions based on the 
     * AWSConfiguration.
     */
    private void registerConfigSignInProviders() {
        LOG.log(Level.FINE, "Using the SignInProviderConfig from `awsconfiguration.json`.");
        final IdentityManager identityManager = IdentityManager.getDefaultIdentityManager();

        if (isConfigurationKeyPresent(USER_POOLS)) {
            // TODO: 
            throw new UnsupportedOperationException("Not supported yet.");
//            identityManager.addSignInProvider(CognitoUserPoolsSignInProvider.class);
        }

        if (isConfigurationKeyPresent(FACEBOOK)) {
            // TODO: 
            throw new UnsupportedOperationException("Not supported yet.");
//            identityManager.addSignInProvider(FacebookSignInProvider.class);
        }

        if (isConfigurationKeyPresent(GOOGLE)) {
            // TODO: 
            throw new UnsupportedOperationException("Not supported yet.");
//            identityManager.addSignInProvider(GoogleSignInProvider.class);
        }
    }

    /**
     * Check if the AWSConfiguration has the specified key.
     * 
     * @param configurationKey The key for SignIn in AWSConfiguration
     */
    private boolean isConfigurationKeyPresent(final String configurationKey) {
        try {
            JSONObject jsonObject = this.awsConfiguration.optJsonObject(configurationKey);
            if (configurationKey.equals(GOOGLE)) {
                return jsonObject != null && jsonObject.getString(GOOGLE_WEBAPP_CONFIG_KEY) != null;
            } else {
                return jsonObject != null;
            }
        } catch (final Exception exception) {
            LOG.log(Level.FINE, configurationKey + " not found in `awsconfiguration.json`");
            return false;
        }
    }
    /**
     * Resume any previusly signed-in session.
     * 
     * @param startupAuthResultHandler The Callback function for resuming an auth session
     */
    private void resumeSession(final StartupAuthResultHandler startupAuthResultHandler) {
        IdentityManager
            .getDefaultIdentityManager()
            .resumeSession(startupAuthResultHandler);
    }

    /**
     * {@code InitializeBuilder} accepts and retrieves
     * the optional parameters necessary for initializing the 
     * {@link AWSMobileClient} to work on.
     */
    public class InitializeBuilder {

        private AWSConfiguration awsConfiguration;
        private SignInProviderConfig[] signInProviderConfig;

        /**
         * Constructor that intializes the InitializeBuilder
         */
        public InitializeBuilder() {
            this.awsConfiguration = null;
            this.signInProviderConfig = null;
        }

        /**
         * Sets the AWSConfiguration object passed in
         * @param awsConfiguration The instance of awsconfiguration.json
         * @return instance of InitializeBuilder
         */
        public InitializeBuilder awsConfiguration(final AWSConfiguration awsConfiguration) {
            this.awsConfiguration = awsConfiguration;
            return this;
        }

        /**
         * Sets the list of SignInProviderConfig passed in
         * @param providersConfig The SignInProvider class with permissions
         * @return instance of InitializeBuilder
         */
        public InitializeBuilder signInProviders(final SignInProviderConfig... providersConfig) {
            this.signInProviderConfig = providersConfig;
            return this;
        }

        /**
         * Retrieve the instance of AWSConfiguration.
         * @return awsConfiguration
         */
        public AWSConfiguration getAwsConfiguration() {
            return this.awsConfiguration;
        }

        /**
         * Retrieve the instance of SignInProvider class and permissions.
         * @return signInProviderConfig
         */
        public SignInProviderConfig[] getSignInProviderConfig() {
            return this.signInProviderConfig;
        }

        /**
         * Initialize the {@link AWSMobileClient} with the parameters passed in. 
         */
        public void execute() {
            initializeWithBuilder(this);
        }
    }

    /**
     * The wrapper class for SignInProvider class and 
     * the permissions necessary for provider.
     */
    public class SignInProviderConfig {

        /** SignInProvider class. */
        private Class<? extends SignInProvider> signInProvider;

        /** Permissions for the SignInProvider. */
        private String[] providerPermissions;

        /**
         * Constructor
         * @param signInProvider        The class object of the SignInProvider
         * @param providerPermissions   Provider permissions if applicable
         */
        public SignInProviderConfig(final Class<? extends SignInProvider> signInProvider,
                                    final String... providerPermissions) {
            this.signInProvider = signInProvider;
            this.providerPermissions = providerPermissions;
        }

        /**
         * Retrieve the SignInProvider class
         * @return The SignInProvider class
         */
        public Class<? extends SignInProvider> getSignInProviderClass() {
            return this.signInProvider;
        }

        /**
         * Retrieve the provider permissions
         * @return the provider permissions
         */
        public String[] getProviderPermissions() {
            return this.providerPermissions;
        }
    }
}
