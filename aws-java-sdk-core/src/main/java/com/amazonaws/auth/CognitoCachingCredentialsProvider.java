/**
 * Copyright 2011-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */

package com.amazonaws.auth;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.mobile.config.AWSConfiguration;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.cognitoidentity.model.NotAuthorizedException;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.util.VersionInfoUtils;
import com.gluonhq.charm.down.Services;
import com.gluonhq.charm.down.plugins.SettingsService;

import java.util.Date;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This credentials provider is intended for Android applications. It offers the
 * ability to persist the Cognito identity id in {@link SharedPreferences}.
 * Furthermore, it caches session credentials so as to reduce the number of
 * network requests. This is the provider to use with a custom identity
 * provider, which should be an extension of AWSAbstractCognitoIdentityProvider.
 * This will consume an identity provider, as well. If one is passed in to a
 * constructor, then that one is the one that is consumed, but if not/a
 * constructor that doesn't take an identity provider is used, then the Cognito
 * identity provider is used by default.
 * <p>
 * Note: if you haven't yet associated your IAM roles with your identity pool,
 * please do so via the Cognito console before using this constructor. You will
 * get an InvalidIdentityPoolConfigurationException if you use it and have not.
 * </p>
 *
 * <pre>
 * // initiate a credentials provider
 * CognitoCachingCredentialsProvider provider = new CognitoCachingCredentialsProvider(
 *         context,
 *         &quot;identityPoolId&quot;,
 *         Regions.US_EAST_1);
 *
 * // use the provider to instantiate an AWS client
 * AmazonSNS snsClient = new AmazonSNSClient(provider);
 *
 * // If the user is authenticated through login with Amazon, you can set the map
 * // of token to the provider
 * Map&lt;String, String&gt; logins = new HashMap&lt;String, String&gt;();
 * logins.put(""www.amazon.com", "login with Amazon token");
 * provider.setLogins(logins);
 *
 * // Note: Please reuse the provider when possible.
 *
 * //The existing constructor will work without doing so, but will not use the enhanced flow:
 * CognitoCachingCredentialsProvider provider = new CognitoCachingCredentialsProvider(
 *         context,
 *         &quot;awsAccountId&quot;,
 *         &quot;identityPoolId&quot;,
 *         &quot;unauthRoleArn&quot;,
 *         &quot;authRoleArn&quot;,
 *         Regions.US_EAST_1);
 * </pre>
 */
public class CognitoCachingCredentialsProvider
        extends CognitoCredentialsProvider {

    private static final Logger LOG = Logger.getLogger(CognitoCachingCredentialsProvider.class.getName());
    
    private static final String USER_AGENT = CognitoCachingCredentialsProvider.class.getName()
            + "/" + VersionInfoUtils.getVersion();
    private final SettingsService prefs;
    private String identityId;

    private static final String ID_KEY = "identityId";
    private static final String AK_KEY = "accessKey";
    private static final String SK_KEY = "secretKey";
    private static final String ST_KEY = "sessionToken";
    private static final String EXP_KEY = "expirationDate";

    volatile boolean needIdentityRefresh = false;

    private final IdentityChangedListener listener = new IdentityChangedListener() {
        @Override
        public void identityChanged(String oldIdentityId, String newIdentityId) {
            LOG.log(Level.FINE,  "Identity id is changed");
            saveIdentityId(newIdentityId);
            clearCredentials();
        }
    };

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request, using
     * the basic authentication flow, to the AWS Security Token Service (STS) to
     * request short-lived session credentials, which will then be returned by
     * this class's {@link #getCredentials()} method.
     *
     * @param accountId The AWS accountId for the account with Amazon Cognito
     * @param identityPoolId The Amazon Cogntio identity pool to use
     * @param unauthRoleArn The ARN of the IAM Role that will be assumed when
     *            unauthenticated
     * @param authRoleArn The ARN of the IAM Role that will be assumed when
     *            authenticated
     * @param region The region to use when contacting Cognito Identity
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(String accountId,
            String identityPoolId, String unauthRoleArn, String authRoleArn, Regions region) throws Throwable {
        super(accountId, identityPoolId, unauthRoleArn, authRoleArn, region);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request, using
     * the basic authentication flow, to the AWS Security Token Service (STS) to
     * request short-lived session credentials, which will then be returned by
     * this class's {@link #getCredentials()} method.
     * <p>
     * This version of the constructor allows you to specify a client
     * configuration for the Amazon Cognito and STS clients.
     * </p>
     *
     * @param accountId The AWS accountId for the account with Amazon Cognito
     * @param identityPoolId The Amazon Cognito identity pool to use
     * @param unauthRoleArn The ARN of the IAM Role that will be assumed when
     *            unauthenticated
     * @param authRoleArn The ARN of the IAM Role that will be assumed when
     *            authenticated
     * @param region The region to use when contacting Cognito Identity
     * @param clientConfiguration Configuration to apply to service clients
     *            created
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(String accountId,
            String identityPoolId, String unauthRoleArn, String authRoleArn, Regions region,
            ClientConfiguration clientConfiguration) throws Throwable {
        super(accountId, identityPoolId, unauthRoleArn, authRoleArn, region, clientConfiguration);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request to
     * Cognito, using the enhanced flow, to get short lived session credentials,
     * which will then be returned by this class's {@link #getCredentials()}
     * method.
     * <p>
     * Note: if you haven't yet associated your IAM roles with your identity
     * pool, please do so via the Cognito console before using this constructor.
     * You will get an InvalidIdentityPoolConfigurationException if you use it
     * and have not. The existing constructor (mirroring this one but with roles
     * and an account id) will work without doing so, but will not use the
     * enhanced flow.
     * </p>
     *
     * @param identityPoolId The Amazon Cognito identity pool to use
     * @param region The region to use when contacting Cognito Identity
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(String identityPoolId, Regions region) throws Throwable {
        super(identityPoolId, region);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request to
     * Cognito, using the enhanced flow, to get short lived session credentials,
     * which will then be returned by this class's {@link #getCredentials()}
     * method.
     * <p>
     * Note: if you haven't yet associated your IAM roles with your identity
     * pool, please do so via the Cognito console before using this constructor.
     * You will get an InvalidIdentityPoolConfigurationException if you use it
     * and have not. The existing constructor (mirroring this one but with roles
     * and an account id) will work without doing so, but will not use the
     * enhanced flow.
     * </p>
     *
     * Example json file:
     * {
     *     "CredentialsProvider": {
     *         "CognitoIdentity": {
     *             "Default": {
     *                 "PoolId": "us-east-1:example-pool-id1234",
     *                 "Region": "us-east-1"
     *             }
     *         }
     *     }
     * }
     *
     * @param awsConfiguration The configuration holding you identity pool id
     *                         and the region to use when contacting
     *                         Cognito Identity
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(AWSConfiguration awsConfiguration) throws Throwable {
        super(awsConfiguration);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request to
     * Cognito, using the enhanced flow, to get short lived session credentials,
     * which will then be returned by this class's {@link #getCredentials()}
     * method.
     * <p>
     * This version of the constructor allows you to specify a client
     * configuration for the Amazon Cognito client.
     * </p>
     * <p>
     * Note: if you haven't yet associated your IAM roles with your identity
     * pool, please do so via the Cognito console before using this constructor.
     * You will get an InvalidIdentityPoolConfigurationException if you use it
     * and have not. The existing constructor (mirroring this one but with roles
     * and an account id) will work without doing so, but will not use the
     * enhanced flow.
     * </p>
     *
     * @param identityPoolId The Amazon Cognito identity pool to use
     * @param region The region to use when contacting Cognito Identity
     * @param clientConfiguration Configuration to apply to service clients
     *            created
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(String identityPoolId,
            Regions region, ClientConfiguration clientConfiguration) throws Throwable {
        super(identityPoolId, region, clientConfiguration);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * use the specified Amazon Cognito identity pool to make a request to the
     * AWS Security Token Service (STS) to get short-lived session credentials,
     * which will then be returned by this class's {@link #getCredentials()}
     * method.
     * <p>
     * This version of the constructor allows you to specify the Amazon Cognito
     * and STS client to use.
     * </p>
     * <p>
     * Set the roles and stsClient to null to use the enhanced authentication
     * flow, not contacting STS. Otherwise the basic flow will be used.
     * </p>
     *
     * @param accountId The AWS accountId for the account with Amazon Cognito
     * @param identityPoolId The Amazon Cogntio identity pool to use
     * @param unauthArn The ARN of the IAM Role that will be assumed when
     *            unauthenticated
     * @param authArn The ARN of the IAM Role that will be assumed when
     *            authenticated
     * @param cibClient Preconfigured CognitoIdentity client to make requests
     *            with
     * @param stsClient Preconfigured STS client to make requests with
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(String accountId,
            String identityPoolId, String unauthArn, String authArn,
            AmazonCognitoIdentityClient cibClient, AWSSecurityTokenService stsClient) throws Throwable {
        super(accountId, identityPoolId, unauthArn, authArn, cibClient, stsClient);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * set up a link to the provider passed in using the basic authentication
     * flow to get get short-lived credentials from STS, which can be retrieved
     * from {@link #getCredentials()}
     * <p>
     * This version of the constructor allows you to specify your own Identity
     * Provider class.
     * </p>
     *
     * @param provider a reference to the provider in question, including what's
     *            needed to interact with it to later connect with STS
     * @param unauthArn the unauthArn, for use with the STS call
     * @param authArn the authArn, for use with the STS call
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(AWSCognitoIdentityProvider provider,
            String unauthArn, String authArn) throws Throwable {
        super(provider, unauthArn, authArn);

        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * set up a link to the provider passed in to use the basic authentication
     * flow to get short-lived credentials from STS, which can be retrieved from
     * {@link #getCredentials()}
     * <p>
     * This version of the constructor allows you to specify your own Identity
     * Provider class, and the STS client to use.
     * </p>
     *
     * @param provider a reference to the provider in question, including what's
     *            needed to interact with it to later connect with STS
     * @param unauthArn the unauthArn, for use with the STS call
     * @param authArn the authArn, for use with the STS call
     * @param stsClient the sts endpoint to get session credentials from
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(AWSCognitoIdentityProvider provider,
            String unauthArn, String authArn, AWSSecurityTokenService stsClient) throws Throwable {
        super(provider, unauthArn, authArn, stsClient);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * set up a link to the provider passed in using the enhanced authentication
     * flow to get short-lived credentials from Amazon Cognito, which can be
     * retrieved from {@link #getCredentials()}
     * <p>
     * This version of the constructor allows you to specify your own Identity
     * Provider class.
     * </p>
     * <p>
     * Note: if you haven't yet associated your IAM roles with your identity
     * pool, please do so via the Cognito console before using this constructor.
     * You will get an InvalidIdentityPoolConfigurationException if you use it
     * and have not. The existing constructor (mirroring this one but with
     * roles) will work without doing so, but will not use the enhanced flow.
     * </p>
     *
     * @param provider a reference to the provider in question, including what's
     *            needed to interact with it to later connect with Amazon
     *            Cognito
     * @param region The region to use when contacting Cognito
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(AWSCognitoIdentityProvider provider,
            Regions region) throws Throwable {
        super(provider, region);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    /**
     * Constructs a new {@link CognitoCachingCredentialsProvider}, which will
     * set up a link to the provider passed in using the enhanced authentication
     * flow to get short-lived credentials from Amazon Cognito, which can be
     * retrieved from {@link #getCredentials()}
     * <p>
     * This version of the constructor allows you to specify your own Identity
     * Provider class and the configuration for the Amazon Cognito client.
     * </p>
     * <p>
     * Note: if you haven't yet associated your IAM roles with your identity
     * pool, please do so via the Cognito console before using this constructor.
     * You will get an InvalidIdentityPoolConfigurationException if you use it
     * and have not. The existing constructor (mirroring this one but with
     * roles) will work without doing so, but will not use the enhanced flow.
     * </p>
     *
     * @param provider a reference to the provider in question, including what's
     *            needed to interact with it to later connect with Amazon
     *            Cognito
     * @param clientConfiguration Configuration to apply to service clients
     *            created
     * @param region The region to use when contacting Cognito Identity
     * @throws java.lang.Throwable
     */
    public CognitoCachingCredentialsProvider(AWSCognitoIdentityProvider provider,
            Regions region, ClientConfiguration clientConfiguration) throws Throwable {
        super(provider, region, clientConfiguration);
        
        this.prefs = Services.get(SettingsService.class)
                .orElseThrow(new Supplier() {
                    @Override
                    public Object get() {
                        throw new RuntimeException("Error accessing Settings Service"); 
                    }
                });
        
        initialize();
    }

    private void initialize() {
        checkUpgrade();
        this.identityId = getCachedIdentityId();
        loadCachedCredentials();
        registerIdentityChangedListener(listener);
    }

    /**
     * Gets the Cognito identity id of the user. The first time when this method
     * is called, a network request will be made to retrieve a new identity id.
     * After that it's saved in {@link SharedPreferences}. Please don't call it
     * in the main thread.
     *
     * @return identity id of the user
     */
    @Override
    public String getIdentityId() {
        // If a login has been added, this condition is met
        // and refresh is called to update the id
        if (needIdentityRefresh) {
            needIdentityRefresh = false;
            refresh();
            identityId = super.getIdentityId();
            saveIdentityId(identityId);
        }

        // try to get the ID from SharedPreferences
        this.identityId = getCachedIdentityId();
        if (this.identityId == null) {
            identityId = super.getIdentityId();
            saveIdentityId(identityId);
        }
        return identityId;
    }

    @Override
    public AWSSessionCredentials getCredentials() {
    	credentialsLock.writeLock().lock();
        try {
        	// return only if the credentials are valid
        	if (sessionCredentials == null) {
        		loadCachedCredentials();
        	}

        	if ((sessionCredentialsExpiration != null) && !needsNewSession()) {
        		return sessionCredentials;
        	}
        	// super will validate loaded credentials
        	// and fetch if necessary
        	super.getCredentials();

        	// null check before saving credentials
        	if (sessionCredentialsExpiration != null) {
        		saveCredentials(sessionCredentials, 
        				sessionCredentialsExpiration.getTime());
        	}
        	return sessionCredentials;
        } catch (NotAuthorizedException e) {
            LOG.log(Level.WARNING,  "Failure to get credentials", e);
            if (getLogins() != null) {
                // If the fetch failed then the credentials don't
                // match the current id, so clear them
                super.setIdentityId(null);
                super.getCredentials();
                return sessionCredentials;
            }
            else {
                throw e;
            }
        } finally {
        	credentialsLock.writeLock().unlock();
        }
    }
    
    @Override
    public void refresh() {
    	credentialsLock.writeLock().lock();
    	try {
    		super.refresh();

    		// null check before saving credentials
    		if (sessionCredentialsExpiration != null) {
    			saveCredentials(sessionCredentials,
    					sessionCredentialsExpiration.getTime());
    		}
    	} finally {
    		credentialsLock.writeLock().unlock();
    	}
    }

    @Override
    public void setLogins(Map<String, String> logins) {
    	credentialsLock.writeLock().lock();
    	try {
    		super.setLogins(logins);
    		// A new login has been added, so an identity refresh is necessary
    		needIdentityRefresh = true;
    		// clear cached credentials
    		clearCredentials();
    	} finally {
    		credentialsLock.writeLock().unlock();
    	}
    }

    /*
     * (non-Javadoc)
     * @see com.amazonaws.auth.CognitoCredentialsProvider#clear() Clears the AWS
     * credentials and the identity id.
     */
    @Override
    public void clear() {
        super.clear();

        // clear cached identity id and credentials
        clearPrefs();
    }

    /*
     * (non-Javadoc)
     * @see com.amazonaws.auth.CognitoCredentialsProvider#clearCredentials()
     * Clears the AWS credentials
     */
    @Override
    public void clearCredentials() {
    	credentialsLock.writeLock().lock();
    	try {
            super.clearCredentials();
            LOG.log(Level.FINE,  "Clearing credentials from SharedPreferences");
            prefs.remove(namespace(AK_KEY));
            prefs.remove(namespace(SK_KEY));
            prefs.remove(namespace(ST_KEY));
            prefs.remove(namespace(EXP_KEY));
    	} finally {
            credentialsLock.writeLock().unlock();
    	}
    }

    /**
     * Gets the cached identity id without making a network request.
     *
     * @return cached identity id, null if it doesn't exist
     */
    public String getCachedIdentityId() {
        String cachedIdentityId = prefs.retrieve(namespace(ID_KEY));
        if (cachedIdentityId != null && identityId == null) {
            super.setIdentityId(cachedIdentityId);
        }
        return cachedIdentityId;
    }

    /**
     * Load the credentials from prefs
     */
    void loadCachedCredentials() {
        LOG.log(Level.FINE,  "Loading credentials from SharedPreferences");
        final String value = prefs.retrieve(namespace(EXP_KEY));
        if (value != null && ! value.isEmpty()) {
            sessionCredentialsExpiration = new Date(Long.valueOf(value));
        } else {
            sessionCredentialsExpiration = null;
        }
        // make sure we have valid data in prefs
        boolean hasAK = prefs.retrieve(namespace(AK_KEY)) != null;
        boolean hasSK = prefs.retrieve(namespace(SK_KEY)) != null;
        boolean hasST = prefs.retrieve(namespace(ST_KEY)) != null;
        if (!hasAK || !hasSK || !hasST) {
            LOG.log(Level.FINE,  "No valid credentials found in SharedPreferences");
            sessionCredentialsExpiration = null;
            return;
        }
        String AK = prefs.retrieve(namespace(AK_KEY));
        String SK = prefs.retrieve(namespace(SK_KEY));
        String ST = prefs.retrieve(namespace(ST_KEY));

        sessionCredentials = new BasicSessionCredentials(AK, SK, ST);
    }

    /**
     * Save the credentials to SharedPreferences
     */
    private void saveCredentials(AWSSessionCredentials sessionCredentials,
            long time) {
        LOG.log(Level.FINE,  "Saving credentials to SharedPreferences");
        if (sessionCredentials != null) {
            prefs.store(namespace(AK_KEY), sessionCredentials.getAWSAccessKeyId());
            prefs.store(namespace(SK_KEY), sessionCredentials.getAWSSecretKey());
            prefs.store(namespace(ST_KEY), sessionCredentials.getSessionToken());
            prefs.store(namespace(EXP_KEY), Long.toString(time));
        }
    }

    /**
     * clear cached identity id and credentials Save the Amazon Cognito Identity
     * Id to SharedPreferences
     */
    private void saveIdentityId(String identityId) {
        LOG.log(Level.FINE,  "Saving identity id to SharedPreferences");
        this.identityId = identityId;

        prefs.store(namespace(ID_KEY), identityId);
    }

    @Override
    protected String getUserAgent() {
        return USER_AGENT;
    }

    // To support multiple identity pools in the same app, namespacing the keys
    // in shared preferences is required. However, in order to keep previously
    // saved identity id, unauthenticated id in particular, a check of the id
    // under the old key is performed. If there is one, save it under the new
    // namespace.
    private void checkUpgrade() {
        // check identity id without namespace
        if (prefs.retrieve(ID_KEY) != null) {
            LOG.log(Level.INFO, 
                    "Identity id without namespace is detected. It will be saved under new namespace.");
            // save identity id
            String identityId = prefs.retrieve(ID_KEY);
            clearPrefs();
            prefs.store(namespace(ID_KEY), identityId);
        }
    }

    // prefix the key with identity pool id
    private String namespace(String key) {
        return getIdentityPoolId() + "." + key;
    }
    
    private void clearPrefs() {
        prefs.remove(namespace(ID_KEY));
        prefs.remove(namespace(AK_KEY));
        prefs.remove(namespace(SK_KEY));
        prefs.remove(namespace(ST_KEY));
        prefs.remove(namespace(EXP_KEY));
    }
}
