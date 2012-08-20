package org.elasticsearch.river.ldap;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.indices.IndexAlreadyExistsException;
import org.elasticsearch.river.AbstractRiverComponent;
import org.elasticsearch.river.River;
import org.elasticsearch.river.RiverIndexName;
import org.elasticsearch.river.RiverName;
import org.elasticsearch.river.RiverSettings;

/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
public class LdapRiver extends AbstractRiverComponent implements River {

    private final Client client;

    @RiverIndexName
    private String riverIndexName;

    private final String userDn;
    private final String credentials;
    private final String host;
    private final int port;
    private final boolean ssl;

    private final String filter;
    private final String baseDn;
    private final String[] attributes;
    private final String[] fields;
    private final String scope;

    private final TimeValue poll;

    private final String indexName;
    private final String typeName;

    private final int bulkSize;
    private final TimeValue bulkTimeout;

    private volatile boolean closed = false;

    private volatile Thread thread;

    @SuppressWarnings("unchecked")
    @Inject
    protected LdapRiver(RiverName riverName, RiverSettings settings, Client client) {
        super(riverName, settings);
        this.client = client;

        if (settings.settings().containsKey("ldap")) {
            Map<String, Object> ldapSettings = (Map<String, Object>) settings.settings().get("ldap");

            userDn = XContentMapValues.nodeStringValue(ldapSettings.get("userDn"), null);
            credentials = XContentMapValues.nodeStringValue(ldapSettings.get("credentials"), null);
            host = XContentMapValues.nodeStringValue(ldapSettings.get("host"), null);
            port = XContentMapValues.nodeIntegerValue(ldapSettings.get("port"), 389);
            ssl = XContentMapValues.nodeBooleanValue(ldapSettings.get("ssl"), false);
            filter = XContentMapValues.nodeStringValue(ldapSettings.get("filter"), null);
            baseDn = XContentMapValues.nodeStringValue(ldapSettings.get("baseDn"), null);
            scope = XContentMapValues.nodeStringValue(ldapSettings.get("scope"), null);

            if(XContentMapValues.isArray(ldapSettings.get("attributes"))) {
                List<Object> values = (List<Object>) ldapSettings.get("attributes");
                attributes = new String[values.size()];
                for (int i = 0; i < attributes.length; i++) {
                    attributes[i] = values.get(i).toString();
                }
            } else {
                attributes = null;
            }
            if(XContentMapValues.isArray(ldapSettings.get("fields"))) {
                List<Object> values = (List<Object>) ldapSettings.get("fields");
                fields = new String[values.size()];
                for (int i = 0; i < fields.length; i++) {
                    fields[i] = values.get(i).toString();
                }
            } else {
                fields = null;
            }
            poll = XContentMapValues.nodeTimeValue(ldapSettings.get("poll"), TimeValue.timeValueMinutes(60));

        } else {
            userDn = null;
            credentials = null;
            host = null;
            port = 389;
            ssl = false;
            filter = null;
            baseDn = null;
            attributes = null;
            fields = null;
            scope = null;
            poll = TimeValue.timeValueMinutes(60);
        }
        if (settings.settings().containsKey("index")) {
            Map<String, Object> indexSettings = (Map<String, Object>) settings.settings().get("index");
            indexName = XContentMapValues.nodeStringValue(indexSettings.get("index"), "jdbc");
            typeName = XContentMapValues.nodeStringValue(indexSettings.get("type"), "jdbc");
            bulkSize = XContentMapValues.nodeIntegerValue(indexSettings.get("bulk_size"), 100);
            if (indexSettings.containsKey("bulk_timeout")) {
                bulkTimeout = TimeValue.parseTimeValue(XContentMapValues.nodeStringValue(indexSettings.get("bulk_timeout"), "60s"),
                                                       TimeValue.timeValueMillis(60000));
            } else {
                bulkTimeout = TimeValue.timeValueMillis(60000);
            }
        } else {
            indexName = "ldap";
            typeName = "ldap";
            bulkSize = 100;
            bulkTimeout = TimeValue.timeValueMillis(60000);
        }
    }

    public void start() {
        logger.info("starting ldap river [{}]: host [{}], port [{}], ssl [{}], username [{}], filter [{}], search [{}], indexing to [{}]/[{}], poll [{}]", 
                    riverIndexName, host, port, ssl, userDn, filter, baseDn, indexName, typeName, poll);
        try {
            client.admin().indices().prepareCreate(indexName).execute().actionGet();
        } catch (Exception e) {
            if (ExceptionsHelper.unwrapCause(e) instanceof IndexAlreadyExistsException) {
                logger.debug("ldap river index [{}] already exists", e, indexName);
            } else {
                logger.warn("failed to create index [{}], disabling river...", e, indexName);
                return;
            }
        }
        thread = EsExecutors.daemonThreadFactory(settings.globalSettings(), "ldap_river").newThread(new LdapReader());
        thread.start();
    }

    public void close() {
        if (closed) {
            return;
        }
        logger.info("closing Ldap river");
        if (thread != null) {
            thread.interrupt();
        }
        closed = true;
    }

    private class LdapReader implements Runnable {

        public void run() {
            
            BulkRequestBuilder bulkRequest = client.prepareBulk();
            
            while (true) {
                if (closed) {
                    return;
                }

                DirContext ctx = null;
                Properties environment = new Properties();

                try {
                    environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                    environment.put(Context.SECURITY_AUTHENTICATION, "simple");
                    environment.put(Context.SECURITY_PRINCIPAL, userDn);
                    environment.put(Context.SECURITY_CREDENTIALS, credentials);

                    if (ssl) {
                        environment.put(Context.PROVIDER_URL, "ldaps://" + host + ":" + port);
                        environment.put(Context.SECURITY_PROTOCOL, "ssl");
                    } else {
                        environment.put(Context.PROVIDER_URL, "ldap://" + host + ":" + port);
                    }

                    ctx = new InitialDirContext(environment);
                    int count = 0;

                    SearchControls constraints = new SearchControls();
                    if ("object".equalsIgnoreCase(scope)) {
                        constraints.setSearchScope(SearchControls.OBJECT_SCOPE);
                    } else if ("onelevel".equalsIgnoreCase(scope)) {
                        constraints.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                    } else {
                        constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    }
                    
                    if (attributes != null && attributes.length > 0) {
                        constraints.setReturningAttributes(attributes);
                    }
                    
                    long start = System.currentTimeMillis();
                    NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, constraints);
                    logger.debug("LDAP search executed in {} ms", System.currentTimeMillis() - start);
                    
                    while (results != null && results.hasMore()) {
                        
                        SearchResult sr = (SearchResult) results.next();
                        
                        IndexRequest indexRequest = new IndexRequest(indexName);
                        
                        XContentBuilder builder = jsonBuilder();
                        builder.startObject();
                        
                        String dn = sr.getName();
                        logger.debug("Reading ldap object dn [{}]", dn);
                        
                        Attributes ldapAttributes = sr.getAttributes();
                        NamingEnumeration<String> ldapAttributesIds = ldapAttributes.getIDs();
                        while (ldapAttributesIds.hasMoreElements()) {
                            String id = ldapAttributesIds.next();
                            logger.debug("\treading attribute id [{}]", id);
                            
                            List<String> fieldValues = new ArrayList<String>();
                            Attribute attribute = ldapAttributes.get(id);
                            NamingEnumeration<?> values = attribute.getAll();
                            while (values.hasMoreElements()) {
                                Object value = values.next();
                                logger.debug("\t\tvalue: [{}]", value.toString());
                                fieldValues.add(value.toString());
                            }
                            String fieldName = resolveFieldName(id);
                            if(fieldValues.size() > 1){
                                builder.array(fieldName, fieldValues.toArray());
                            } else {
                                if (!"_id".equals(fieldName)) {
                                    builder.field(fieldName, fieldValues.get(0));
                                } else {
                                    indexRequest.id(fieldValues.get(0));
                                }
                            }
                        }

                        builder.endObject();
                        
                        indexRequest.type(typeName).source(builder);
                        bulkRequest.add(indexRequest);
                        count++;
                        
                        if((count % bulkSize) == 0){
                            BulkResponse bulkResponse = bulkRequest.execute().actionGet(bulkTimeout);
                            logger.info("{} objects indexed with ", count, bulkResponse.hasFailures()? "errors" : "success");
                        }                        
                    }
                    
                    if(bulkRequest.numberOfActions() > 0){
                        BulkResponse bulkResponse = bulkRequest.setRefresh(true).execute().actionGet(bulkTimeout);
                        logger.info("{} objects indexed with ", count, bulkResponse.hasFailures()? "errors" : "success");
                    }

                } catch (Exception e) {
                    logger.error("Exception when accessing to LDAP server", e);
                } finally {
                    try {
                        ctx.close();
                    } catch (NamingException e) {
                        logger.error("Exception when closing LDAP context", e);
                    }
                }
                
                if (poll.millis() > 0L) {
                    logger.info("now, ldap river {} waiting for {} ms", riverIndexName, poll);
                    try {
                        Thread.sleep(poll.millis());
                    } catch (InterruptedException e) {
                        logger.error("Exception on Thread.sleep()", e);
                    }
                }
            }
        }
        
        private String resolveFieldName(String id) {
            if ((fields != null) && (fields.length > 0)) {
                int i = Arrays.binarySearch(attributes, id);
                if ((i >= 0) && (i < fields.length)) {
                    return fields[i];
                }
            }
            return id;
        }
    }
}
