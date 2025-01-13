# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181001

from .listing_package import ListingPackage
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ContainerListingPackage(ListingPackage):
    """
    A listing package for container.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ContainerListingPackage object with values from keyword arguments. The default value of the :py:attr:`~oci.marketplace.models.ContainerListingPackage.package_type` attribute
        of this class is ``CONTAINER`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param description:
            The value to assign to the description property of this ContainerListingPackage.
        :type description: str

        :param listing_id:
            The value to assign to the listing_id property of this ContainerListingPackage.
        :type listing_id: str

        :param version:
            The value to assign to the version property of this ContainerListingPackage.
        :type version: str

        :param package_type:
            The value to assign to the package_type property of this ContainerListingPackage.
            Allowed values for this property are: "ORCHESTRATION", "IMAGE", "CONTAINER", "KUBERNETES"
        :type package_type: str

        :param pricing:
            The value to assign to the pricing property of this ContainerListingPackage.
        :type pricing: oci.marketplace.models.PricingModel

        :param resource_id:
            The value to assign to the resource_id property of this ContainerListingPackage.
        :type resource_id: str

        :param time_created:
            The value to assign to the time_created property of this ContainerListingPackage.
        :type time_created: datetime

        :param operating_system:
            The value to assign to the operating_system property of this ContainerListingPackage.
        :type operating_system: oci.marketplace.models.OperatingSystem

        :param regions:
            The value to assign to the regions property of this ContainerListingPackage.
        :type regions: list[oci.marketplace.models.Region]

        """
        self.swagger_types = {
            'description': 'str',
            'listing_id': 'str',
            'version': 'str',
            'package_type': 'str',
            'pricing': 'PricingModel',
            'resource_id': 'str',
            'time_created': 'datetime',
            'operating_system': 'OperatingSystem',
            'regions': 'list[Region]'
        }

        self.attribute_map = {
            'description': 'description',
            'listing_id': 'listingId',
            'version': 'version',
            'package_type': 'packageType',
            'pricing': 'pricing',
            'resource_id': 'resourceId',
            'time_created': 'timeCreated',
            'operating_system': 'operatingSystem',
            'regions': 'regions'
        }

        self._description = None
        self._listing_id = None
        self._version = None
        self._package_type = None
        self._pricing = None
        self._resource_id = None
        self._time_created = None
        self._operating_system = None
        self._regions = None
        self._package_type = 'CONTAINER'

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
