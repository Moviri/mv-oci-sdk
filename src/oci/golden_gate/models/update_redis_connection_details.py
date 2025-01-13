# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200407

from .update_connection_details import UpdateConnectionDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateRedisConnectionDetails(UpdateConnectionDetails):
    """
    The information to update a Redis Database Connection.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateRedisConnectionDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.golden_gate.models.UpdateRedisConnectionDetails.connection_type` attribute
        of this class is ``REDIS`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param connection_type:
            The value to assign to the connection_type property of this UpdateRedisConnectionDetails.
            Allowed values for this property are: "GOLDENGATE", "KAFKA", "KAFKA_SCHEMA_REGISTRY", "MYSQL", "JAVA_MESSAGE_SERVICE", "MICROSOFT_SQLSERVER", "OCI_OBJECT_STORAGE", "ORACLE", "AZURE_DATA_LAKE_STORAGE", "POSTGRESQL", "AZURE_SYNAPSE_ANALYTICS", "SNOWFLAKE", "AMAZON_S3", "HDFS", "ORACLE_NOSQL", "MONGODB", "AMAZON_KINESIS", "AMAZON_REDSHIFT", "DB2", "REDIS", "ELASTICSEARCH", "GENERIC", "GOOGLE_CLOUD_STORAGE", "GOOGLE_BIGQUERY"
        :type connection_type: str

        :param display_name:
            The value to assign to the display_name property of this UpdateRedisConnectionDetails.
        :type display_name: str

        :param description:
            The value to assign to the description property of this UpdateRedisConnectionDetails.
        :type description: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this UpdateRedisConnectionDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this UpdateRedisConnectionDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param vault_id:
            The value to assign to the vault_id property of this UpdateRedisConnectionDetails.
        :type vault_id: str

        :param key_id:
            The value to assign to the key_id property of this UpdateRedisConnectionDetails.
        :type key_id: str

        :param nsg_ids:
            The value to assign to the nsg_ids property of this UpdateRedisConnectionDetails.
        :type nsg_ids: list[str]

        :param subnet_id:
            The value to assign to the subnet_id property of this UpdateRedisConnectionDetails.
        :type subnet_id: str

        :param routing_method:
            The value to assign to the routing_method property of this UpdateRedisConnectionDetails.
            Allowed values for this property are: "SHARED_SERVICE_ENDPOINT", "SHARED_DEPLOYMENT_ENDPOINT", "DEDICATED_ENDPOINT"
        :type routing_method: str

        :param does_use_secret_ids:
            The value to assign to the does_use_secret_ids property of this UpdateRedisConnectionDetails.
        :type does_use_secret_ids: bool

        :param servers:
            The value to assign to the servers property of this UpdateRedisConnectionDetails.
        :type servers: str

        :param security_protocol:
            The value to assign to the security_protocol property of this UpdateRedisConnectionDetails.
        :type security_protocol: str

        :param authentication_type:
            The value to assign to the authentication_type property of this UpdateRedisConnectionDetails.
        :type authentication_type: str

        :param username:
            The value to assign to the username property of this UpdateRedisConnectionDetails.
        :type username: str

        :param password:
            The value to assign to the password property of this UpdateRedisConnectionDetails.
        :type password: str

        :param password_secret_id:
            The value to assign to the password_secret_id property of this UpdateRedisConnectionDetails.
        :type password_secret_id: str

        :param trust_store:
            The value to assign to the trust_store property of this UpdateRedisConnectionDetails.
        :type trust_store: str

        :param trust_store_secret_id:
            The value to assign to the trust_store_secret_id property of this UpdateRedisConnectionDetails.
        :type trust_store_secret_id: str

        :param trust_store_password:
            The value to assign to the trust_store_password property of this UpdateRedisConnectionDetails.
        :type trust_store_password: str

        :param trust_store_password_secret_id:
            The value to assign to the trust_store_password_secret_id property of this UpdateRedisConnectionDetails.
        :type trust_store_password_secret_id: str

        :param key_store:
            The value to assign to the key_store property of this UpdateRedisConnectionDetails.
        :type key_store: str

        :param key_store_secret_id:
            The value to assign to the key_store_secret_id property of this UpdateRedisConnectionDetails.
        :type key_store_secret_id: str

        :param key_store_password:
            The value to assign to the key_store_password property of this UpdateRedisConnectionDetails.
        :type key_store_password: str

        :param key_store_password_secret_id:
            The value to assign to the key_store_password_secret_id property of this UpdateRedisConnectionDetails.
        :type key_store_password_secret_id: str

        :param redis_cluster_id:
            The value to assign to the redis_cluster_id property of this UpdateRedisConnectionDetails.
        :type redis_cluster_id: str

        """
        self.swagger_types = {
            'connection_type': 'str',
            'display_name': 'str',
            'description': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'vault_id': 'str',
            'key_id': 'str',
            'nsg_ids': 'list[str]',
            'subnet_id': 'str',
            'routing_method': 'str',
            'does_use_secret_ids': 'bool',
            'servers': 'str',
            'security_protocol': 'str',
            'authentication_type': 'str',
            'username': 'str',
            'password': 'str',
            'password_secret_id': 'str',
            'trust_store': 'str',
            'trust_store_secret_id': 'str',
            'trust_store_password': 'str',
            'trust_store_password_secret_id': 'str',
            'key_store': 'str',
            'key_store_secret_id': 'str',
            'key_store_password': 'str',
            'key_store_password_secret_id': 'str',
            'redis_cluster_id': 'str'
        }

        self.attribute_map = {
            'connection_type': 'connectionType',
            'display_name': 'displayName',
            'description': 'description',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'vault_id': 'vaultId',
            'key_id': 'keyId',
            'nsg_ids': 'nsgIds',
            'subnet_id': 'subnetId',
            'routing_method': 'routingMethod',
            'does_use_secret_ids': 'doesUseSecretIds',
            'servers': 'servers',
            'security_protocol': 'securityProtocol',
            'authentication_type': 'authenticationType',
            'username': 'username',
            'password': 'password',
            'password_secret_id': 'passwordSecretId',
            'trust_store': 'trustStore',
            'trust_store_secret_id': 'trustStoreSecretId',
            'trust_store_password': 'trustStorePassword',
            'trust_store_password_secret_id': 'trustStorePasswordSecretId',
            'key_store': 'keyStore',
            'key_store_secret_id': 'keyStoreSecretId',
            'key_store_password': 'keyStorePassword',
            'key_store_password_secret_id': 'keyStorePasswordSecretId',
            'redis_cluster_id': 'redisClusterId'
        }

        self._connection_type = None
        self._display_name = None
        self._description = None
        self._freeform_tags = None
        self._defined_tags = None
        self._vault_id = None
        self._key_id = None
        self._nsg_ids = None
        self._subnet_id = None
        self._routing_method = None
        self._does_use_secret_ids = None
        self._servers = None
        self._security_protocol = None
        self._authentication_type = None
        self._username = None
        self._password = None
        self._password_secret_id = None
        self._trust_store = None
        self._trust_store_secret_id = None
        self._trust_store_password = None
        self._trust_store_password_secret_id = None
        self._key_store = None
        self._key_store_secret_id = None
        self._key_store_password = None
        self._key_store_password_secret_id = None
        self._redis_cluster_id = None
        self._connection_type = 'REDIS'

    @property
    def servers(self):
        """
        Gets the servers of this UpdateRedisConnectionDetails.
        Comma separated list of Redis server addresses, specified as host:port entries, where :port is optional.
        If port is not specified, it defaults to 6379.
        Used for establishing the initial connection to the Redis cluster.
        Example: `\"server1.example.com:6379,server2.example.com:6379\"`


        :return: The servers of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._servers

    @servers.setter
    def servers(self, servers):
        """
        Sets the servers of this UpdateRedisConnectionDetails.
        Comma separated list of Redis server addresses, specified as host:port entries, where :port is optional.
        If port is not specified, it defaults to 6379.
        Used for establishing the initial connection to the Redis cluster.
        Example: `\"server1.example.com:6379,server2.example.com:6379\"`


        :param servers: The servers of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._servers = servers

    @property
    def security_protocol(self):
        """
        Gets the security_protocol of this UpdateRedisConnectionDetails.
        Security protocol for Redis.


        :return: The security_protocol of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._security_protocol

    @security_protocol.setter
    def security_protocol(self, security_protocol):
        """
        Sets the security_protocol of this UpdateRedisConnectionDetails.
        Security protocol for Redis.


        :param security_protocol: The security_protocol of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._security_protocol = security_protocol

    @property
    def authentication_type(self):
        """
        Gets the authentication_type of this UpdateRedisConnectionDetails.
        Authenticationentication type for the Redis database.


        :return: The authentication_type of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._authentication_type

    @authentication_type.setter
    def authentication_type(self, authentication_type):
        """
        Sets the authentication_type of this UpdateRedisConnectionDetails.
        Authenticationentication type for the Redis database.


        :param authentication_type: The authentication_type of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._authentication_type = authentication_type

    @property
    def username(self):
        """
        Gets the username of this UpdateRedisConnectionDetails.
        The username Oracle GoldenGate uses to connect the associated system of the given technology.
        This username must already exist and be available by the system/application to be connected to
        and must conform to the case sensitivty requirments defined in it.


        :return: The username of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """
        Sets the username of this UpdateRedisConnectionDetails.
        The username Oracle GoldenGate uses to connect the associated system of the given technology.
        This username must already exist and be available by the system/application to be connected to
        and must conform to the case sensitivty requirments defined in it.


        :param username: The username of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._username = username

    @property
    def password(self):
        """
        Gets the password of this UpdateRedisConnectionDetails.
        The password Oracle GoldenGate uses to connect the associated system of the given technology.
        It must conform to the specific security requirements including length, case sensitivity, and so on.


        :return: The password of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, password):
        """
        Sets the password of this UpdateRedisConnectionDetails.
        The password Oracle GoldenGate uses to connect the associated system of the given technology.
        It must conform to the specific security requirements including length, case sensitivity, and so on.


        :param password: The password of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._password = password

    @property
    def password_secret_id(self):
        """
        Gets the password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the password is stored.
        The password Oracle GoldenGate uses to connect the associated system of the given technology.
        It must conform to the specific security requirements including length, case sensitivity, and so on.
        If secretId is used plaintext field must not be provided.
        Note: When provided, 'password' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The password_secret_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._password_secret_id

    @password_secret_id.setter
    def password_secret_id(self, password_secret_id):
        """
        Sets the password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the password is stored.
        The password Oracle GoldenGate uses to connect the associated system of the given technology.
        It must conform to the specific security requirements including length, case sensitivity, and so on.
        If secretId is used plaintext field must not be provided.
        Note: When provided, 'password' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param password_secret_id: The password_secret_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._password_secret_id = password_secret_id

    @property
    def trust_store(self):
        """
        Gets the trust_store of this UpdateRedisConnectionDetails.
        The base64 encoded content of the TrustStore file.


        :return: The trust_store of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._trust_store

    @trust_store.setter
    def trust_store(self, trust_store):
        """
        Sets the trust_store of this UpdateRedisConnectionDetails.
        The base64 encoded content of the TrustStore file.


        :param trust_store: The trust_store of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._trust_store = trust_store

    @property
    def trust_store_secret_id(self):
        """
        Gets the trust_store_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret that stores the content of the TrustStore file.
        Note: When provided, 'trustStore' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The trust_store_secret_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._trust_store_secret_id

    @trust_store_secret_id.setter
    def trust_store_secret_id(self, trust_store_secret_id):
        """
        Sets the trust_store_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret that stores the content of the TrustStore file.
        Note: When provided, 'trustStore' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param trust_store_secret_id: The trust_store_secret_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._trust_store_secret_id = trust_store_secret_id

    @property
    def trust_store_password(self):
        """
        Gets the trust_store_password of this UpdateRedisConnectionDetails.
        The TrustStore password.


        :return: The trust_store_password of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._trust_store_password

    @trust_store_password.setter
    def trust_store_password(self, trust_store_password):
        """
        Sets the trust_store_password of this UpdateRedisConnectionDetails.
        The TrustStore password.


        :param trust_store_password: The trust_store_password of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._trust_store_password = trust_store_password

    @property
    def trust_store_password_secret_id(self):
        """
        Gets the trust_store_password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the Redis TrustStore password is stored.
        Note: When provided, 'trustStorePassword' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The trust_store_password_secret_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._trust_store_password_secret_id

    @trust_store_password_secret_id.setter
    def trust_store_password_secret_id(self, trust_store_password_secret_id):
        """
        Sets the trust_store_password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the Redis TrustStore password is stored.
        Note: When provided, 'trustStorePassword' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param trust_store_password_secret_id: The trust_store_password_secret_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._trust_store_password_secret_id = trust_store_password_secret_id

    @property
    def key_store(self):
        """
        Gets the key_store of this UpdateRedisConnectionDetails.
        The base64 encoded content of the KeyStore file.


        :return: The key_store of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._key_store

    @key_store.setter
    def key_store(self, key_store):
        """
        Sets the key_store of this UpdateRedisConnectionDetails.
        The base64 encoded content of the KeyStore file.


        :param key_store: The key_store of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._key_store = key_store

    @property
    def key_store_secret_id(self):
        """
        Gets the key_store_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret that stores the content of the KeyStore file.
        Note: When provided, 'keyStore' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The key_store_secret_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._key_store_secret_id

    @key_store_secret_id.setter
    def key_store_secret_id(self, key_store_secret_id):
        """
        Sets the key_store_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret that stores the content of the KeyStore file.
        Note: When provided, 'keyStore' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param key_store_secret_id: The key_store_secret_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._key_store_secret_id = key_store_secret_id

    @property
    def key_store_password(self):
        """
        Gets the key_store_password of this UpdateRedisConnectionDetails.
        The KeyStore password.


        :return: The key_store_password of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._key_store_password

    @key_store_password.setter
    def key_store_password(self, key_store_password):
        """
        Sets the key_store_password of this UpdateRedisConnectionDetails.
        The KeyStore password.


        :param key_store_password: The key_store_password of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._key_store_password = key_store_password

    @property
    def key_store_password_secret_id(self):
        """
        Gets the key_store_password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the Redis KeyStore password is stored.
        Note: When provided, 'keyStorePassword' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The key_store_password_secret_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._key_store_password_secret_id

    @key_store_password_secret_id.setter
    def key_store_password_secret_id(self, key_store_password_secret_id):
        """
        Sets the key_store_password_secret_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Secret where the Redis KeyStore password is stored.
        Note: When provided, 'keyStorePassword' field must not be provided.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param key_store_password_secret_id: The key_store_password_secret_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._key_store_password_secret_id = key_store_password_secret_id

    @property
    def redis_cluster_id(self):
        """
        Gets the redis_cluster_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Redis cluster.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The redis_cluster_id of this UpdateRedisConnectionDetails.
        :rtype: str
        """
        return self._redis_cluster_id

    @redis_cluster_id.setter
    def redis_cluster_id(self, redis_cluster_id):
        """
        Sets the redis_cluster_id of this UpdateRedisConnectionDetails.
        The `OCID`__ of the Redis cluster.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param redis_cluster_id: The redis_cluster_id of this UpdateRedisConnectionDetails.
        :type: str
        """
        self._redis_cluster_id = redis_cluster_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
