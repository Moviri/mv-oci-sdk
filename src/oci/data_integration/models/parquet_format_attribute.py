# coding: utf-8
# Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .abstract_format_attribute import AbstractFormatAttribute
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ParquetFormatAttribute(AbstractFormatAttribute):
    """
    The PARQUET format attribute.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ParquetFormatAttribute object with values from keyword arguments. The default value of the :py:attr:`~oci.data_integration.models.ParquetFormatAttribute.model_type` attribute
        of this class is ``PARQUET_FORMAT`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param model_type:
            The value to assign to the model_type property of this ParquetFormatAttribute.
            Allowed values for this property are: "JSON_FORMAT", "CSV_FORMAT", "AVRO_FORMAT"
        :type model_type: str

        :param is_file_pattern:
            The value to assign to the is_file_pattern property of this ParquetFormatAttribute.
        :type is_file_pattern: bool

        :param compression:
            The value to assign to the compression property of this ParquetFormatAttribute.
        :type compression: str

        """
        self.swagger_types = {
            'model_type': 'str',
            'is_file_pattern': 'bool',
            'compression': 'str'
        }

        self.attribute_map = {
            'model_type': 'modelType',
            'is_file_pattern': 'isFilePattern',
            'compression': 'compression'
        }

        self._model_type = None
        self._is_file_pattern = None
        self._compression = None
        self._model_type = 'PARQUET_FORMAT'

    @property
    def compression(self):
        """
        Gets the compression of this ParquetFormatAttribute.
        The compression for the file.


        :return: The compression of this ParquetFormatAttribute.
        :rtype: str
        """
        return self._compression

    @compression.setter
    def compression(self, compression):
        """
        Sets the compression of this ParquetFormatAttribute.
        The compression for the file.


        :param compression: The compression of this ParquetFormatAttribute.
        :type: str
        """
        self._compression = compression

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other