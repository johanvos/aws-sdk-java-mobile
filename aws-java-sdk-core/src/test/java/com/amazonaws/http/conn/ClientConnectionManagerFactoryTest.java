/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.http.conn;

import static org.junit.Assert.assertTrue;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.ClientConnectionRequest;
import org.apache.http.conn.ManagedClientConnection;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

public class ClientConnectionManagerFactoryTest {
    ClientConnectionManager noop = new ClientConnectionManager() {
        @Override
        public SchemeRegistry getSchemeRegistry() {
            return null;
        }

        @Override
        public ClientConnectionRequest requestConnection(HttpRoute route,
                Object state) {
            return null;
        }

        @Override
        public void releaseConnection(ManagedClientConnection conn,
                long validDuration, TimeUnit timeUnit) {
        }

        @Override
        public void closeIdleConnections(long idletime, TimeUnit tunit) {
        }

        @Override
        public void closeExpiredConnections() {
        }

        @Override
        public void shutdown() {
        }
    };

    @Test
    public void wrapOnce() {
        ClientConnectionManager wrapped = ClientConnectionManagerFactory.wrap(noop);
        assertTrue(wrapped instanceof Wrapped);
    }

    @Test(expected = IllegalArgumentException.class)
    public void wrapTwice() {
        ClientConnectionManager wrapped = ClientConnectionManagerFactory.wrap(noop);
        ClientConnectionManagerFactory.wrap(wrapped);
    }
}
