/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2025 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.picketlink.identity.federation.bindings.stspool;

import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig;
import org.picketlink.identity.federation.core.wstrust.STSClientCreationCallBack;
import org.picketlink.identity.federation.core.wstrust.STSClientPool;
import org.picketlink.identity.federation.core.wstrust.STSClientFactory;


/**
 * Simple factory for creating {@link STSClient}s.
 *
 */
public final class STSClientPoolFactory implements STSClientPool {

    private STSClientPoolInternal stsClientPoolInternal;

    private STSClientPoolFactory() {
        stsClientPoolInternal = new STSClientPoolInternal();
    }

    private static class LazySTSClientFactory {
        private static final STSClientPoolFactory INSTANCE = new STSClientPoolFactory();
    }

    /**
     * Get instance of {@link STSClientPool}.
     *
     * @return {@link STSClientPool} instance
     */
    public static STSClientPool getPoolInstance() {
        STSClientPoolFactory cf = LazySTSClientFactory.INSTANCE;
        STSClientFactory.setInstance(cf);
        return cf;
    }

    /**
     * This method initializes sub pool of clients by given configuration data and returns client from that pool.
     *
     * When pooling is disabled it does nothing.
     *
     * @param config to construct the pool of clients
     */
    public void createPool(final STSClientConfig config) {
        createPool(STSClientPoolInternal.DEFAULT_NUM_STS_CLIENTS, config);
    }

    /**
     * This method initializes sub pool of clients by given configuration data and returns client from that pool.
     * initialNumberOfClients is used to initialize the pool for the given number of clients.
     *
     * When pooling is disabled it does nothing.
     *
     * @param initialNumberOfClients initial number of clients in the pool
     * @param config to construct the pool of clients
     */
    public void createPool(int initialNumberOfClients, final STSClientConfig config) {
        stsClientPoolInternal.initialize(initialNumberOfClients, config);
    }

    /**
     * This method initializes sub pool of clients by given configuration data.
     * initialNumberOfClients is used to initialize the pool for the given number of clients.
     *
     * When pooling is disabled it does nothing.
     *
     * @param initialNumberOfClients initial number of clients in the pool
     * @param callBack which provide configuration
     */

    public void createPool(int initialNumberOfClients, final STSClientCreationCallBack callBack) {
        stsClientPoolInternal.initialize(initialNumberOfClients, callBack);
    }

    /**
     * Destroys client sub pool denoted by given config.
     *
     * @param config {@link STSClientConfiguration} to find client sub pool to destroy
     */
    public void destroyPool(final STSClientConfig config) {
        stsClientPoolInternal.destroy(config);
    }


   /**
    * Destroy all the pools attached to given module name.
    *
    * @param moduleName module name to destroy pools or "" or null to destroy default module's pools.
    */
    public void destroyPool(final String moduleName) {
        stsClientPoolInternal.destroy(moduleName);
    }

    /**
     * Returns given {@link STSClient} back to the sub pool of clients.
     * Sub pool is determined automatically from client configuration.
     *
     * @param {@link STSClient} to return back to the sub pool of clients
     */
    public void returnClient(final STSClient stsClient) {
        stsClientPoolInternal.putIn(stsClient);
    }

    /**
     * Get STSClient from sub pool denoted by config.
     * @param config {@link STSClientConfiguration} to find client sub pool
     * @return {@link STSClient} from the sub pool of clients
     */
    public STSClient getClient(final STSClientConfig config) {
        STSClient client = stsClientPoolInternal.takeOut(config);
        if (client == null) {
            // non pooled client
            return new STSClient(config);
        }
        return client;
    }

    /**
     * Checks whether given config has already sub pool of clients created.
     *
     * @param config {@link STSClientConfiguration} to find client sub pool
     * @return true if config was already used as sub pool key
     */
    public boolean configExists(final STSClientConfig config) {
        return stsClientPoolInternal.isConfigInitialized(config);
    }

}
