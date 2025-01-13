# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210630


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class RepositoryAnalyticsDetails(object):
    """
    Details of the user configured settings for viewing the metrics.
    """

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "COMMITS"
    REPOSITORY_METRICS_COMMITS = "COMMITS"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "LINES_ADDED"
    REPOSITORY_METRICS_LINES_ADDED = "LINES_ADDED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "LINES_DELETED"
    REPOSITORY_METRICS_LINES_DELETED = "LINES_DELETED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_CREATED"
    REPOSITORY_METRICS_PULL_REQUEST_CREATED = "PULL_REQUEST_CREATED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_MERGED"
    REPOSITORY_METRICS_PULL_REQUEST_MERGED = "PULL_REQUEST_MERGED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_DECLINED"
    REPOSITORY_METRICS_PULL_REQUEST_DECLINED = "PULL_REQUEST_DECLINED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS"
    REPOSITORY_METRICS_PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS = "PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_REVIEW_DURATION_IN_DAYS"
    REPOSITORY_METRICS_PULL_REQUEST_REVIEW_DURATION_IN_DAYS = "PULL_REQUEST_REVIEW_DURATION_IN_DAYS"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_APPROVED"
    REPOSITORY_METRICS_PULL_REQUEST_APPROVED = "PULL_REQUEST_APPROVED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_REVIEWED"
    REPOSITORY_METRICS_PULL_REQUEST_REVIEWED = "PULL_REQUEST_REVIEWED"

    #: A constant which can be used with the repository_metrics property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "PULL_REQUEST_COMMENTS"
    REPOSITORY_METRICS_PULL_REQUEST_COMMENTS = "PULL_REQUEST_COMMENTS"

    #: A constant which can be used with the aggregation_duration property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "DAILY"
    AGGREGATION_DURATION_DAILY = "DAILY"

    #: A constant which can be used with the aggregation_duration property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "WEEKLY"
    AGGREGATION_DURATION_WEEKLY = "WEEKLY"

    #: A constant which can be used with the aggregation_duration property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "MONTHLY"
    AGGREGATION_DURATION_MONTHLY = "MONTHLY"

    #: A constant which can be used with the aggregation_duration property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "YEARLY"
    AGGREGATION_DURATION_YEARLY = "YEARLY"

    #: A constant which can be used with the group_by property of a RepositoryAnalyticsDetails.
    #: This constant has a value of "AUTHOR"
    GROUP_BY_AUTHOR = "AUTHOR"

    def __init__(self, **kwargs):
        """
        Initializes a new RepositoryAnalyticsDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param author_email:
            The value to assign to the author_email property of this RepositoryAnalyticsDetails.
        :type author_email: str

        :param repository_metrics:
            The value to assign to the repository_metrics property of this RepositoryAnalyticsDetails.
            Allowed values for items in this list are: "COMMITS", "LINES_ADDED", "LINES_DELETED", "PULL_REQUEST_CREATED", "PULL_REQUEST_MERGED", "PULL_REQUEST_DECLINED", "PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS", "PULL_REQUEST_REVIEW_DURATION_IN_DAYS", "PULL_REQUEST_APPROVED", "PULL_REQUEST_REVIEWED", "PULL_REQUEST_COMMENTS"
        :type repository_metrics: list[str]

        :param aggregation_duration:
            The value to assign to the aggregation_duration property of this RepositoryAnalyticsDetails.
            Allowed values for this property are: "DAILY", "WEEKLY", "MONTHLY", "YEARLY"
        :type aggregation_duration: str

        :param start_time:
            The value to assign to the start_time property of this RepositoryAnalyticsDetails.
        :type start_time: datetime

        :param end_time:
            The value to assign to the end_time property of this RepositoryAnalyticsDetails.
        :type end_time: datetime

        :param group_by:
            The value to assign to the group_by property of this RepositoryAnalyticsDetails.
            Allowed values for this property are: "AUTHOR"
        :type group_by: str

        """
        self.swagger_types = {
            'author_email': 'str',
            'repository_metrics': 'list[str]',
            'aggregation_duration': 'str',
            'start_time': 'datetime',
            'end_time': 'datetime',
            'group_by': 'str'
        }

        self.attribute_map = {
            'author_email': 'authorEmail',
            'repository_metrics': 'repositoryMetrics',
            'aggregation_duration': 'aggregationDuration',
            'start_time': 'startTime',
            'end_time': 'endTime',
            'group_by': 'groupBy'
        }

        self._author_email = None
        self._repository_metrics = None
        self._aggregation_duration = None
        self._start_time = None
        self._end_time = None
        self._group_by = None

    @property
    def author_email(self):
        """
        Gets the author_email of this RepositoryAnalyticsDetails.
        Email address of the author.


        :return: The author_email of this RepositoryAnalyticsDetails.
        :rtype: str
        """
        return self._author_email

    @author_email.setter
    def author_email(self, author_email):
        """
        Sets the author_email of this RepositoryAnalyticsDetails.
        Email address of the author.


        :param author_email: The author_email of this RepositoryAnalyticsDetails.
        :type: str
        """
        self._author_email = author_email

    @property
    def repository_metrics(self):
        """
        **[Required]** Gets the repository_metrics of this RepositoryAnalyticsDetails.
        The name of the metric to be filtered.

        Allowed values for items in this list are: "COMMITS", "LINES_ADDED", "LINES_DELETED", "PULL_REQUEST_CREATED", "PULL_REQUEST_MERGED", "PULL_REQUEST_DECLINED", "PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS", "PULL_REQUEST_REVIEW_DURATION_IN_DAYS", "PULL_REQUEST_APPROVED", "PULL_REQUEST_REVIEWED", "PULL_REQUEST_COMMENTS"


        :return: The repository_metrics of this RepositoryAnalyticsDetails.
        :rtype: list[str]
        """
        return self._repository_metrics

    @repository_metrics.setter
    def repository_metrics(self, repository_metrics):
        """
        Sets the repository_metrics of this RepositoryAnalyticsDetails.
        The name of the metric to be filtered.


        :param repository_metrics: The repository_metrics of this RepositoryAnalyticsDetails.
        :type: list[str]
        """
        allowed_values = ["COMMITS", "LINES_ADDED", "LINES_DELETED", "PULL_REQUEST_CREATED", "PULL_REQUEST_MERGED", "PULL_REQUEST_DECLINED", "PULL_REQUEST_REVIEW_START_DURATION_IN_DAYS", "PULL_REQUEST_REVIEW_DURATION_IN_DAYS", "PULL_REQUEST_APPROVED", "PULL_REQUEST_REVIEWED", "PULL_REQUEST_COMMENTS"]

        if repository_metrics and repository_metrics is not NONE_SENTINEL:
            for value in repository_metrics:
                if not value_allowed_none_or_none_sentinel(value, allowed_values):
                    raise ValueError(
                        f"Invalid value for `repository_metrics`, must be None or one of {allowed_values}"
                    )
        self._repository_metrics = repository_metrics

    @property
    def aggregation_duration(self):
        """
        Gets the aggregation_duration of this RepositoryAnalyticsDetails.
        Metrics aggregated for the defined period.

        Allowed values for this property are: "DAILY", "WEEKLY", "MONTHLY", "YEARLY"


        :return: The aggregation_duration of this RepositoryAnalyticsDetails.
        :rtype: str
        """
        return self._aggregation_duration

    @aggregation_duration.setter
    def aggregation_duration(self, aggregation_duration):
        """
        Sets the aggregation_duration of this RepositoryAnalyticsDetails.
        Metrics aggregated for the defined period.


        :param aggregation_duration: The aggregation_duration of this RepositoryAnalyticsDetails.
        :type: str
        """
        allowed_values = ["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]
        if not value_allowed_none_or_none_sentinel(aggregation_duration, allowed_values):
            raise ValueError(
                f"Invalid value for `aggregation_duration`, must be None or one of {allowed_values}"
            )
        self._aggregation_duration = aggregation_duration

    @property
    def start_time(self):
        """
        **[Required]** Gets the start_time of this RepositoryAnalyticsDetails.
        The beginning of the metric data query time range.


        :return: The start_time of this RepositoryAnalyticsDetails.
        :rtype: datetime
        """
        return self._start_time

    @start_time.setter
    def start_time(self, start_time):
        """
        Sets the start_time of this RepositoryAnalyticsDetails.
        The beginning of the metric data query time range.


        :param start_time: The start_time of this RepositoryAnalyticsDetails.
        :type: datetime
        """
        self._start_time = start_time

    @property
    def end_time(self):
        """
        Gets the end_time of this RepositoryAnalyticsDetails.
        The end of the metric data query time range.


        :return: The end_time of this RepositoryAnalyticsDetails.
        :rtype: datetime
        """
        return self._end_time

    @end_time.setter
    def end_time(self, end_time):
        """
        Sets the end_time of this RepositoryAnalyticsDetails.
        The end of the metric data query time range.


        :param end_time: The end_time of this RepositoryAnalyticsDetails.
        :type: datetime
        """
        self._end_time = end_time

    @property
    def group_by(self):
        """
        Gets the group_by of this RepositoryAnalyticsDetails.
        Attribute by which metric data has to be grouped

        Allowed values for this property are: "AUTHOR"


        :return: The group_by of this RepositoryAnalyticsDetails.
        :rtype: str
        """
        return self._group_by

    @group_by.setter
    def group_by(self, group_by):
        """
        Sets the group_by of this RepositoryAnalyticsDetails.
        Attribute by which metric data has to be grouped


        :param group_by: The group_by of this RepositoryAnalyticsDetails.
        :type: str
        """
        allowed_values = ["AUTHOR"]
        if not value_allowed_none_or_none_sentinel(group_by, allowed_values):
            raise ValueError(
                f"Invalid value for `group_by`, must be None or one of {allowed_values}"
            )
        self._group_by = group_by

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
