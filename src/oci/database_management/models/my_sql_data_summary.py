# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20201101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class MySqlDataSummary(object):
    """
    The SQL performance data record for a specific SQL query.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new MySqlDataSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param schema_name:
            The value to assign to the schema_name property of this MySqlDataSummary.
        :type schema_name: str

        :param digest:
            The value to assign to the digest property of this MySqlDataSummary.
        :type digest: str

        :param digest_text:
            The value to assign to the digest_text property of this MySqlDataSummary.
        :type digest_text: str

        :param count_star:
            The value to assign to the count_star property of this MySqlDataSummary.
        :type count_star: float

        :param sum_timer_wait:
            The value to assign to the sum_timer_wait property of this MySqlDataSummary.
        :type sum_timer_wait: float

        :param min_timer_wait:
            The value to assign to the min_timer_wait property of this MySqlDataSummary.
        :type min_timer_wait: float

        :param avg_timer_wait:
            The value to assign to the avg_timer_wait property of this MySqlDataSummary.
        :type avg_timer_wait: float

        :param max_timer_wait:
            The value to assign to the max_timer_wait property of this MySqlDataSummary.
        :type max_timer_wait: float

        :param sum_lock_time:
            The value to assign to the sum_lock_time property of this MySqlDataSummary.
        :type sum_lock_time: float

        :param sum_errors:
            The value to assign to the sum_errors property of this MySqlDataSummary.
        :type sum_errors: float

        :param sum_warnings:
            The value to assign to the sum_warnings property of this MySqlDataSummary.
        :type sum_warnings: float

        :param sum_rows_affected:
            The value to assign to the sum_rows_affected property of this MySqlDataSummary.
        :type sum_rows_affected: float

        :param sum_rows_sent:
            The value to assign to the sum_rows_sent property of this MySqlDataSummary.
        :type sum_rows_sent: float

        :param sum_rows_examined:
            The value to assign to the sum_rows_examined property of this MySqlDataSummary.
        :type sum_rows_examined: float

        :param sum_created_temp_disk_tables:
            The value to assign to the sum_created_temp_disk_tables property of this MySqlDataSummary.
        :type sum_created_temp_disk_tables: float

        :param sum_created_temp_tables:
            The value to assign to the sum_created_temp_tables property of this MySqlDataSummary.
        :type sum_created_temp_tables: float

        :param sum_select_full_join:
            The value to assign to the sum_select_full_join property of this MySqlDataSummary.
        :type sum_select_full_join: float

        :param sum_select_full_range_join:
            The value to assign to the sum_select_full_range_join property of this MySqlDataSummary.
        :type sum_select_full_range_join: float

        :param sum_select_range:
            The value to assign to the sum_select_range property of this MySqlDataSummary.
        :type sum_select_range: float

        :param sum_select_range_check:
            The value to assign to the sum_select_range_check property of this MySqlDataSummary.
        :type sum_select_range_check: float

        :param sum_select_scan:
            The value to assign to the sum_select_scan property of this MySqlDataSummary.
        :type sum_select_scan: float

        :param sum_sort_merge_passes:
            The value to assign to the sum_sort_merge_passes property of this MySqlDataSummary.
        :type sum_sort_merge_passes: float

        :param sum_sort_range:
            The value to assign to the sum_sort_range property of this MySqlDataSummary.
        :type sum_sort_range: float

        :param sum_sort_rows:
            The value to assign to the sum_sort_rows property of this MySqlDataSummary.
        :type sum_sort_rows: float

        :param sum_sort_scan:
            The value to assign to the sum_sort_scan property of this MySqlDataSummary.
        :type sum_sort_scan: float

        :param sum_no_index_used:
            The value to assign to the sum_no_index_used property of this MySqlDataSummary.
        :type sum_no_index_used: float

        :param sum_no_good_index_used:
            The value to assign to the sum_no_good_index_used property of this MySqlDataSummary.
        :type sum_no_good_index_used: float

        :param first_seen:
            The value to assign to the first_seen property of this MySqlDataSummary.
        :type first_seen: datetime

        :param last_seen:
            The value to assign to the last_seen property of this MySqlDataSummary.
        :type last_seen: datetime

        :param quantile95:
            The value to assign to the quantile95 property of this MySqlDataSummary.
        :type quantile95: float

        :param quantile99:
            The value to assign to the quantile99 property of this MySqlDataSummary.
        :type quantile99: float

        :param quantile999:
            The value to assign to the quantile999 property of this MySqlDataSummary.
        :type quantile999: float

        :param heat_wave_offloaded:
            The value to assign to the heat_wave_offloaded property of this MySqlDataSummary.
        :type heat_wave_offloaded: float

        :param heat_wave_out_of_memory:
            The value to assign to the heat_wave_out_of_memory property of this MySqlDataSummary.
        :type heat_wave_out_of_memory: float

        """
        self.swagger_types = {
            'schema_name': 'str',
            'digest': 'str',
            'digest_text': 'str',
            'count_star': 'float',
            'sum_timer_wait': 'float',
            'min_timer_wait': 'float',
            'avg_timer_wait': 'float',
            'max_timer_wait': 'float',
            'sum_lock_time': 'float',
            'sum_errors': 'float',
            'sum_warnings': 'float',
            'sum_rows_affected': 'float',
            'sum_rows_sent': 'float',
            'sum_rows_examined': 'float',
            'sum_created_temp_disk_tables': 'float',
            'sum_created_temp_tables': 'float',
            'sum_select_full_join': 'float',
            'sum_select_full_range_join': 'float',
            'sum_select_range': 'float',
            'sum_select_range_check': 'float',
            'sum_select_scan': 'float',
            'sum_sort_merge_passes': 'float',
            'sum_sort_range': 'float',
            'sum_sort_rows': 'float',
            'sum_sort_scan': 'float',
            'sum_no_index_used': 'float',
            'sum_no_good_index_used': 'float',
            'first_seen': 'datetime',
            'last_seen': 'datetime',
            'quantile95': 'float',
            'quantile99': 'float',
            'quantile999': 'float',
            'heat_wave_offloaded': 'float',
            'heat_wave_out_of_memory': 'float'
        }

        self.attribute_map = {
            'schema_name': 'schemaName',
            'digest': 'digest',
            'digest_text': 'digestText',
            'count_star': 'countStar',
            'sum_timer_wait': 'sumTimerWait',
            'min_timer_wait': 'minTimerWait',
            'avg_timer_wait': 'avgTimerWait',
            'max_timer_wait': 'maxTimerWait',
            'sum_lock_time': 'sumLockTime',
            'sum_errors': 'sumErrors',
            'sum_warnings': 'sumWarnings',
            'sum_rows_affected': 'sumRowsAffected',
            'sum_rows_sent': 'sumRowsSent',
            'sum_rows_examined': 'sumRowsExamined',
            'sum_created_temp_disk_tables': 'sumCreatedTempDiskTables',
            'sum_created_temp_tables': 'sumCreatedTempTables',
            'sum_select_full_join': 'sumSelectFullJoin',
            'sum_select_full_range_join': 'sumSelectFullRangeJoin',
            'sum_select_range': 'sumSelectRange',
            'sum_select_range_check': 'sumSelectRangeCheck',
            'sum_select_scan': 'sumSelectScan',
            'sum_sort_merge_passes': 'sumSortMergePasses',
            'sum_sort_range': 'sumSortRange',
            'sum_sort_rows': 'sumSortRows',
            'sum_sort_scan': 'sumSortScan',
            'sum_no_index_used': 'sumNoIndexUsed',
            'sum_no_good_index_used': 'sumNoGoodIndexUsed',
            'first_seen': 'firstSeen',
            'last_seen': 'lastSeen',
            'quantile95': 'quantile95',
            'quantile99': 'quantile99',
            'quantile999': 'quantile999',
            'heat_wave_offloaded': 'heatWaveOffloaded',
            'heat_wave_out_of_memory': 'heatWaveOutOfMemory'
        }

        self._schema_name = None
        self._digest = None
        self._digest_text = None
        self._count_star = None
        self._sum_timer_wait = None
        self._min_timer_wait = None
        self._avg_timer_wait = None
        self._max_timer_wait = None
        self._sum_lock_time = None
        self._sum_errors = None
        self._sum_warnings = None
        self._sum_rows_affected = None
        self._sum_rows_sent = None
        self._sum_rows_examined = None
        self._sum_created_temp_disk_tables = None
        self._sum_created_temp_tables = None
        self._sum_select_full_join = None
        self._sum_select_full_range_join = None
        self._sum_select_range = None
        self._sum_select_range_check = None
        self._sum_select_scan = None
        self._sum_sort_merge_passes = None
        self._sum_sort_range = None
        self._sum_sort_rows = None
        self._sum_sort_scan = None
        self._sum_no_index_used = None
        self._sum_no_good_index_used = None
        self._first_seen = None
        self._last_seen = None
        self._quantile95 = None
        self._quantile99 = None
        self._quantile999 = None
        self._heat_wave_offloaded = None
        self._heat_wave_out_of_memory = None

    @property
    def schema_name(self):
        """
        **[Required]** Gets the schema_name of this MySqlDataSummary.
        The name of the default schema when executing the query. If a schema is not set as the default, then the value is NULL.


        :return: The schema_name of this MySqlDataSummary.
        :rtype: str
        """
        return self._schema_name

    @schema_name.setter
    def schema_name(self, schema_name):
        """
        Sets the schema_name of this MySqlDataSummary.
        The name of the default schema when executing the query. If a schema is not set as the default, then the value is NULL.


        :param schema_name: The schema_name of this MySqlDataSummary.
        :type: str
        """
        self._schema_name = schema_name

    @property
    def digest(self):
        """
        **[Required]** Gets the digest of this MySqlDataSummary.
        The digest information of the normalized query.


        :return: The digest of this MySqlDataSummary.
        :rtype: str
        """
        return self._digest

    @digest.setter
    def digest(self, digest):
        """
        Sets the digest of this MySqlDataSummary.
        The digest information of the normalized query.


        :param digest: The digest of this MySqlDataSummary.
        :type: str
        """
        self._digest = digest

    @property
    def digest_text(self):
        """
        **[Required]** Gets the digest_text of this MySqlDataSummary.
        The normalized query.


        :return: The digest_text of this MySqlDataSummary.
        :rtype: str
        """
        return self._digest_text

    @digest_text.setter
    def digest_text(self, digest_text):
        """
        Sets the digest_text of this MySqlDataSummary.
        The normalized query.


        :param digest_text: The digest_text of this MySqlDataSummary.
        :type: str
        """
        self._digest_text = digest_text

    @property
    def count_star(self):
        """
        **[Required]** Gets the count_star of this MySqlDataSummary.
        The number Of times the query has been executed.


        :return: The count_star of this MySqlDataSummary.
        :rtype: float
        """
        return self._count_star

    @count_star.setter
    def count_star(self, count_star):
        """
        Sets the count_star of this MySqlDataSummary.
        The number Of times the query has been executed.


        :param count_star: The count_star of this MySqlDataSummary.
        :type: float
        """
        self._count_star = count_star

    @property
    def sum_timer_wait(self):
        """
        **[Required]** Gets the sum_timer_wait of this MySqlDataSummary.
        The total amount of time that has been spent executing the query.


        :return: The sum_timer_wait of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_timer_wait

    @sum_timer_wait.setter
    def sum_timer_wait(self, sum_timer_wait):
        """
        Sets the sum_timer_wait of this MySqlDataSummary.
        The total amount of time that has been spent executing the query.


        :param sum_timer_wait: The sum_timer_wait of this MySqlDataSummary.
        :type: float
        """
        self._sum_timer_wait = sum_timer_wait

    @property
    def min_timer_wait(self):
        """
        **[Required]** Gets the min_timer_wait of this MySqlDataSummary.
        The fastest the query has been executed.


        :return: The min_timer_wait of this MySqlDataSummary.
        :rtype: float
        """
        return self._min_timer_wait

    @min_timer_wait.setter
    def min_timer_wait(self, min_timer_wait):
        """
        Sets the min_timer_wait of this MySqlDataSummary.
        The fastest the query has been executed.


        :param min_timer_wait: The min_timer_wait of this MySqlDataSummary.
        :type: float
        """
        self._min_timer_wait = min_timer_wait

    @property
    def avg_timer_wait(self):
        """
        **[Required]** Gets the avg_timer_wait of this MySqlDataSummary.
        The average execution time.


        :return: The avg_timer_wait of this MySqlDataSummary.
        :rtype: float
        """
        return self._avg_timer_wait

    @avg_timer_wait.setter
    def avg_timer_wait(self, avg_timer_wait):
        """
        Sets the avg_timer_wait of this MySqlDataSummary.
        The average execution time.


        :param avg_timer_wait: The avg_timer_wait of this MySqlDataSummary.
        :type: float
        """
        self._avg_timer_wait = avg_timer_wait

    @property
    def max_timer_wait(self):
        """
        **[Required]** Gets the max_timer_wait of this MySqlDataSummary.
        The slowest the query has been executed.


        :return: The max_timer_wait of this MySqlDataSummary.
        :rtype: float
        """
        return self._max_timer_wait

    @max_timer_wait.setter
    def max_timer_wait(self, max_timer_wait):
        """
        Sets the max_timer_wait of this MySqlDataSummary.
        The slowest the query has been executed.


        :param max_timer_wait: The max_timer_wait of this MySqlDataSummary.
        :type: float
        """
        self._max_timer_wait = max_timer_wait

    @property
    def sum_lock_time(self):
        """
        **[Required]** Gets the sum_lock_time of this MySqlDataSummary.
        The total amount of time that has been spent waiting for table locks.


        :return: The sum_lock_time of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_lock_time

    @sum_lock_time.setter
    def sum_lock_time(self, sum_lock_time):
        """
        Sets the sum_lock_time of this MySqlDataSummary.
        The total amount of time that has been spent waiting for table locks.


        :param sum_lock_time: The sum_lock_time of this MySqlDataSummary.
        :type: float
        """
        self._sum_lock_time = sum_lock_time

    @property
    def sum_errors(self):
        """
        **[Required]** Gets the sum_errors of this MySqlDataSummary.
        The total number of errors that have been encountered executing the query.


        :return: The sum_errors of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_errors

    @sum_errors.setter
    def sum_errors(self, sum_errors):
        """
        Sets the sum_errors of this MySqlDataSummary.
        The total number of errors that have been encountered executing the query.


        :param sum_errors: The sum_errors of this MySqlDataSummary.
        :type: float
        """
        self._sum_errors = sum_errors

    @property
    def sum_warnings(self):
        """
        **[Required]** Gets the sum_warnings of this MySqlDataSummary.
        The total number of warnings that have been encountered executing the query.


        :return: The sum_warnings of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_warnings

    @sum_warnings.setter
    def sum_warnings(self, sum_warnings):
        """
        Sets the sum_warnings of this MySqlDataSummary.
        The total number of warnings that have been encountered executing the query.


        :param sum_warnings: The sum_warnings of this MySqlDataSummary.
        :type: float
        """
        self._sum_warnings = sum_warnings

    @property
    def sum_rows_affected(self):
        """
        **[Required]** Gets the sum_rows_affected of this MySqlDataSummary.
        The total number of rows that have been modified by the query.


        :return: The sum_rows_affected of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_rows_affected

    @sum_rows_affected.setter
    def sum_rows_affected(self, sum_rows_affected):
        """
        Sets the sum_rows_affected of this MySqlDataSummary.
        The total number of rows that have been modified by the query.


        :param sum_rows_affected: The sum_rows_affected of this MySqlDataSummary.
        :type: float
        """
        self._sum_rows_affected = sum_rows_affected

    @property
    def sum_rows_sent(self):
        """
        **[Required]** Gets the sum_rows_sent of this MySqlDataSummary.
        The total number of rows that have been returned (sent) to the client.


        :return: The sum_rows_sent of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_rows_sent

    @sum_rows_sent.setter
    def sum_rows_sent(self, sum_rows_sent):
        """
        Sets the sum_rows_sent of this MySqlDataSummary.
        The total number of rows that have been returned (sent) to the client.


        :param sum_rows_sent: The sum_rows_sent of this MySqlDataSummary.
        :type: float
        """
        self._sum_rows_sent = sum_rows_sent

    @property
    def sum_rows_examined(self):
        """
        **[Required]** Gets the sum_rows_examined of this MySqlDataSummary.
        The total number of rows that have been examined by the query.


        :return: The sum_rows_examined of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_rows_examined

    @sum_rows_examined.setter
    def sum_rows_examined(self, sum_rows_examined):
        """
        Sets the sum_rows_examined of this MySqlDataSummary.
        The total number of rows that have been examined by the query.


        :param sum_rows_examined: The sum_rows_examined of this MySqlDataSummary.
        :type: float
        """
        self._sum_rows_examined = sum_rows_examined

    @property
    def sum_created_temp_disk_tables(self):
        """
        **[Required]** Gets the sum_created_temp_disk_tables of this MySqlDataSummary.
        The total number of On-Disk internal temporary tables that have been created by the query.


        :return: The sum_created_temp_disk_tables of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_created_temp_disk_tables

    @sum_created_temp_disk_tables.setter
    def sum_created_temp_disk_tables(self, sum_created_temp_disk_tables):
        """
        Sets the sum_created_temp_disk_tables of this MySqlDataSummary.
        The total number of On-Disk internal temporary tables that have been created by the query.


        :param sum_created_temp_disk_tables: The sum_created_temp_disk_tables of this MySqlDataSummary.
        :type: float
        """
        self._sum_created_temp_disk_tables = sum_created_temp_disk_tables

    @property
    def sum_created_temp_tables(self):
        """
        **[Required]** Gets the sum_created_temp_tables of this MySqlDataSummary.
        The total number of internal temporary tables (in memory or on disk), which have been created by the query.


        :return: The sum_created_temp_tables of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_created_temp_tables

    @sum_created_temp_tables.setter
    def sum_created_temp_tables(self, sum_created_temp_tables):
        """
        Sets the sum_created_temp_tables of this MySqlDataSummary.
        The total number of internal temporary tables (in memory or on disk), which have been created by the query.


        :param sum_created_temp_tables: The sum_created_temp_tables of this MySqlDataSummary.
        :type: float
        """
        self._sum_created_temp_tables = sum_created_temp_tables

    @property
    def sum_select_full_join(self):
        """
        **[Required]** Gets the sum_select_full_join of this MySqlDataSummary.
        The total number of joins that have performed full table scans as there was no join condition or no index for the join condition. This is the same as the select_full_join status variable.


        :return: The sum_select_full_join of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_select_full_join

    @sum_select_full_join.setter
    def sum_select_full_join(self, sum_select_full_join):
        """
        Sets the sum_select_full_join of this MySqlDataSummary.
        The total number of joins that have performed full table scans as there was no join condition or no index for the join condition. This is the same as the select_full_join status variable.


        :param sum_select_full_join: The sum_select_full_join of this MySqlDataSummary.
        :type: float
        """
        self._sum_select_full_join = sum_select_full_join

    @property
    def sum_select_full_range_join(self):
        """
        **[Required]** Gets the sum_select_full_range_join of this MySqlDataSummary.
        The total number of joins that use a full range search. This is the same as the select_full_range_join status variable.


        :return: The sum_select_full_range_join of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_select_full_range_join

    @sum_select_full_range_join.setter
    def sum_select_full_range_join(self, sum_select_full_range_join):
        """
        Sets the sum_select_full_range_join of this MySqlDataSummary.
        The total number of joins that use a full range search. This is the same as the select_full_range_join status variable.


        :param sum_select_full_range_join: The sum_select_full_range_join of this MySqlDataSummary.
        :type: float
        """
        self._sum_select_full_range_join = sum_select_full_range_join

    @property
    def sum_select_range(self):
        """
        **[Required]** Gets the sum_select_range of this MySqlDataSummary.
        The total number of times the query has used a range search. This is the same as the select_range status variable.


        :return: The sum_select_range of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_select_range

    @sum_select_range.setter
    def sum_select_range(self, sum_select_range):
        """
        Sets the sum_select_range of this MySqlDataSummary.
        The total number of times the query has used a range search. This is the same as the select_range status variable.


        :param sum_select_range: The sum_select_range of this MySqlDataSummary.
        :type: float
        """
        self._sum_select_range = sum_select_range

    @property
    def sum_select_range_check(self):
        """
        **[Required]** Gets the sum_select_range_check of this MySqlDataSummary.
        The total number of joins by the query where the join does not have an index that checks for the index usage after each row. This is the same as the select_range_check status variable.


        :return: The sum_select_range_check of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_select_range_check

    @sum_select_range_check.setter
    def sum_select_range_check(self, sum_select_range_check):
        """
        Sets the sum_select_range_check of this MySqlDataSummary.
        The total number of joins by the query where the join does not have an index that checks for the index usage after each row. This is the same as the select_range_check status variable.


        :param sum_select_range_check: The sum_select_range_check of this MySqlDataSummary.
        :type: float
        """
        self._sum_select_range_check = sum_select_range_check

    @property
    def sum_select_scan(self):
        """
        **[Required]** Gets the sum_select_scan of this MySqlDataSummary.
        The total number of times the query has performed a full table scan on the first table in the join. This is the same as the select_scan status variable.


        :return: The sum_select_scan of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_select_scan

    @sum_select_scan.setter
    def sum_select_scan(self, sum_select_scan):
        """
        Sets the sum_select_scan of this MySqlDataSummary.
        The total number of times the query has performed a full table scan on the first table in the join. This is the same as the select_scan status variable.


        :param sum_select_scan: The sum_select_scan of this MySqlDataSummary.
        :type: float
        """
        self._sum_select_scan = sum_select_scan

    @property
    def sum_sort_merge_passes(self):
        """
        **[Required]** Gets the sum_sort_merge_passes of this MySqlDataSummary.
        The total number of sort merge passes that have been done to sort the result of the query. This is the same as the sort_merge_passes status variable.


        :return: The sum_sort_merge_passes of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_sort_merge_passes

    @sum_sort_merge_passes.setter
    def sum_sort_merge_passes(self, sum_sort_merge_passes):
        """
        Sets the sum_sort_merge_passes of this MySqlDataSummary.
        The total number of sort merge passes that have been done to sort the result of the query. This is the same as the sort_merge_passes status variable.


        :param sum_sort_merge_passes: The sum_sort_merge_passes of this MySqlDataSummary.
        :type: float
        """
        self._sum_sort_merge_passes = sum_sort_merge_passes

    @property
    def sum_sort_range(self):
        """
        **[Required]** Gets the sum_sort_range of this MySqlDataSummary.
        The total number of times a sort was done using ranges. This is the same as the sort_range status variable.


        :return: The sum_sort_range of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_sort_range

    @sum_sort_range.setter
    def sum_sort_range(self, sum_sort_range):
        """
        Sets the sum_sort_range of this MySqlDataSummary.
        The total number of times a sort was done using ranges. This is the same as the sort_range status variable.


        :param sum_sort_range: The sum_sort_range of this MySqlDataSummary.
        :type: float
        """
        self._sum_sort_range = sum_sort_range

    @property
    def sum_sort_rows(self):
        """
        **[Required]** Gets the sum_sort_rows of this MySqlDataSummary.
        The total number of rows sorted. This is the same as the sort_rowsStatus variable.


        :return: The sum_sort_rows of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_sort_rows

    @sum_sort_rows.setter
    def sum_sort_rows(self, sum_sort_rows):
        """
        Sets the sum_sort_rows of this MySqlDataSummary.
        The total number of rows sorted. This is the same as the sort_rowsStatus variable.


        :param sum_sort_rows: The sum_sort_rows of this MySqlDataSummary.
        :type: float
        """
        self._sum_sort_rows = sum_sort_rows

    @property
    def sum_sort_scan(self):
        """
        **[Required]** Gets the sum_sort_scan of this MySqlDataSummary.
        The total number of times a sort was done by scanning the table. This is the same as the sort_scan status variable.


        :return: The sum_sort_scan of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_sort_scan

    @sum_sort_scan.setter
    def sum_sort_scan(self, sum_sort_scan):
        """
        Sets the sum_sort_scan of this MySqlDataSummary.
        The total number of times a sort was done by scanning the table. This is the same as the sort_scan status variable.


        :param sum_sort_scan: The sum_sort_scan of this MySqlDataSummary.
        :type: float
        """
        self._sum_sort_scan = sum_sort_scan

    @property
    def sum_no_index_used(self):
        """
        **[Required]** Gets the sum_no_index_used of this MySqlDataSummary.
        The total number of times no index was used to execute the query.


        :return: The sum_no_index_used of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_no_index_used

    @sum_no_index_used.setter
    def sum_no_index_used(self, sum_no_index_used):
        """
        Sets the sum_no_index_used of this MySqlDataSummary.
        The total number of times no index was used to execute the query.


        :param sum_no_index_used: The sum_no_index_used of this MySqlDataSummary.
        :type: float
        """
        self._sum_no_index_used = sum_no_index_used

    @property
    def sum_no_good_index_used(self):
        """
        **[Required]** Gets the sum_no_good_index_used of this MySqlDataSummary.
        The total number of times no good index was used. This means that the extra column in The EXPLAIN output includes \u201CRange Checked For Each Record.\u201D


        :return: The sum_no_good_index_used of this MySqlDataSummary.
        :rtype: float
        """
        return self._sum_no_good_index_used

    @sum_no_good_index_used.setter
    def sum_no_good_index_used(self, sum_no_good_index_used):
        """
        Sets the sum_no_good_index_used of this MySqlDataSummary.
        The total number of times no good index was used. This means that the extra column in The EXPLAIN output includes \u201CRange Checked For Each Record.\u201D


        :param sum_no_good_index_used: The sum_no_good_index_used of this MySqlDataSummary.
        :type: float
        """
        self._sum_no_good_index_used = sum_no_good_index_used

    @property
    def first_seen(self):
        """
        **[Required]** Gets the first_seen of this MySqlDataSummary.
        The date and time the query was first seen. If the table is truncated, the first seen value is reset.


        :return: The first_seen of this MySqlDataSummary.
        :rtype: datetime
        """
        return self._first_seen

    @first_seen.setter
    def first_seen(self, first_seen):
        """
        Sets the first_seen of this MySqlDataSummary.
        The date and time the query was first seen. If the table is truncated, the first seen value is reset.


        :param first_seen: The first_seen of this MySqlDataSummary.
        :type: datetime
        """
        self._first_seen = first_seen

    @property
    def last_seen(self):
        """
        **[Required]** Gets the last_seen of this MySqlDataSummary.
        The date and time the query was last seen.


        :return: The last_seen of this MySqlDataSummary.
        :rtype: datetime
        """
        return self._last_seen

    @last_seen.setter
    def last_seen(self, last_seen):
        """
        Sets the last_seen of this MySqlDataSummary.
        The date and time the query was last seen.


        :param last_seen: The last_seen of this MySqlDataSummary.
        :type: datetime
        """
        self._last_seen = last_seen

    @property
    def quantile95(self):
        """
        **[Required]** Gets the quantile95 of this MySqlDataSummary.
        The 95th percentile of the query latency. That is, 95% of the queries complete in the time given or in less time.


        :return: The quantile95 of this MySqlDataSummary.
        :rtype: float
        """
        return self._quantile95

    @quantile95.setter
    def quantile95(self, quantile95):
        """
        Sets the quantile95 of this MySqlDataSummary.
        The 95th percentile of the query latency. That is, 95% of the queries complete in the time given or in less time.


        :param quantile95: The quantile95 of this MySqlDataSummary.
        :type: float
        """
        self._quantile95 = quantile95

    @property
    def quantile99(self):
        """
        **[Required]** Gets the quantile99 of this MySqlDataSummary.
        The 99th percentile of the query latency.


        :return: The quantile99 of this MySqlDataSummary.
        :rtype: float
        """
        return self._quantile99

    @quantile99.setter
    def quantile99(self, quantile99):
        """
        Sets the quantile99 of this MySqlDataSummary.
        The 99th percentile of the query latency.


        :param quantile99: The quantile99 of this MySqlDataSummary.
        :type: float
        """
        self._quantile99 = quantile99

    @property
    def quantile999(self):
        """
        **[Required]** Gets the quantile999 of this MySqlDataSummary.
        The 99.9th percentile of the query latency.


        :return: The quantile999 of this MySqlDataSummary.
        :rtype: float
        """
        return self._quantile999

    @quantile999.setter
    def quantile999(self, quantile999):
        """
        Sets the quantile999 of this MySqlDataSummary.
        The 99.9th percentile of the query latency.


        :param quantile999: The quantile999 of this MySqlDataSummary.
        :type: float
        """
        self._quantile999 = quantile999

    @property
    def heat_wave_offloaded(self):
        """
        Gets the heat_wave_offloaded of this MySqlDataSummary.
        The number of query executions offloaded to HeatWave.


        :return: The heat_wave_offloaded of this MySqlDataSummary.
        :rtype: float
        """
        return self._heat_wave_offloaded

    @heat_wave_offloaded.setter
    def heat_wave_offloaded(self, heat_wave_offloaded):
        """
        Sets the heat_wave_offloaded of this MySqlDataSummary.
        The number of query executions offloaded to HeatWave.


        :param heat_wave_offloaded: The heat_wave_offloaded of this MySqlDataSummary.
        :type: float
        """
        self._heat_wave_offloaded = heat_wave_offloaded

    @property
    def heat_wave_out_of_memory(self):
        """
        Gets the heat_wave_out_of_memory of this MySqlDataSummary.
        The number of query executions with HeatWave out-of-memory errors.


        :return: The heat_wave_out_of_memory of this MySqlDataSummary.
        :rtype: float
        """
        return self._heat_wave_out_of_memory

    @heat_wave_out_of_memory.setter
    def heat_wave_out_of_memory(self, heat_wave_out_of_memory):
        """
        Sets the heat_wave_out_of_memory of this MySqlDataSummary.
        The number of query executions with HeatWave out-of-memory errors.


        :param heat_wave_out_of_memory: The heat_wave_out_of_memory of this MySqlDataSummary.
        :type: float
        """
        self._heat_wave_out_of_memory = heat_wave_out_of_memory

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
