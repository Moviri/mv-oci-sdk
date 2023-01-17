# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .entity import Entity
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class KeyValueSelectionEntity(Entity):
    """
    This allows the labeler to apply label the highlighted text from OCR, this includes labelled and unlabelled data.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new KeyValueSelectionEntity object with values from keyword arguments. The default value of the :py:attr:`~oci.data_labeling_service_dataplane.models.KeyValueSelectionEntity.entity_type` attribute
        of this class is ``KEYVALUESELECTION`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param entity_type:
            The value to assign to the entity_type property of this KeyValueSelectionEntity.
            Allowed values for this property are: "GENERIC", "IMAGEOBJECTSELECTION", "TEXTSELECTION", "KEYVALUESELECTION"
        :type entity_type: str

        :param text:
            The value to assign to the text property of this KeyValueSelectionEntity.
        :type text: str

        :param labels:
            The value to assign to the labels property of this KeyValueSelectionEntity.
        :type labels: list[oci.data_labeling_service_dataplane.models.Label]

        :param bounding_polygon:
            The value to assign to the bounding_polygon property of this KeyValueSelectionEntity.
        :type bounding_polygon: oci.data_labeling_service_dataplane.models.BoundingPolygon

        :param rotation:
            The value to assign to the rotation property of this KeyValueSelectionEntity.
        :type rotation: float

        :param confidence:
            The value to assign to the confidence property of this KeyValueSelectionEntity.
        :type confidence: float

        """
        self.swagger_types = {
            'entity_type': 'str',
            'text': 'str',
            'labels': 'list[Label]',
            'bounding_polygon': 'BoundingPolygon',
            'rotation': 'float',
            'confidence': 'float'
        }

        self.attribute_map = {
            'entity_type': 'entityType',
            'text': 'text',
            'labels': 'labels',
            'bounding_polygon': 'boundingPolygon',
            'rotation': 'rotation',
            'confidence': 'confidence'
        }

        self._entity_type = None
        self._text = None
        self._labels = None
        self._bounding_polygon = None
        self._rotation = None
        self._confidence = None
        self._entity_type = 'KEYVALUESELECTION'

    @property
    def text(self):
        """
        **[Required]** Gets the text of this KeyValueSelectionEntity.
        Entity Name.


        :return: The text of this KeyValueSelectionEntity.
        :rtype: str
        """
        return self._text

    @text.setter
    def text(self, text):
        """
        Sets the text of this KeyValueSelectionEntity.
        Entity Name.


        :param text: The text of this KeyValueSelectionEntity.
        :type: str
        """
        self._text = text

    @property
    def labels(self):
        """
        Gets the labels of this KeyValueSelectionEntity.
        A collection of label entities.


        :return: The labels of this KeyValueSelectionEntity.
        :rtype: list[oci.data_labeling_service_dataplane.models.Label]
        """
        return self._labels

    @labels.setter
    def labels(self, labels):
        """
        Sets the labels of this KeyValueSelectionEntity.
        A collection of label entities.


        :param labels: The labels of this KeyValueSelectionEntity.
        :type: list[oci.data_labeling_service_dataplane.models.Label]
        """
        self._labels = labels

    @property
    def bounding_polygon(self):
        """
        **[Required]** Gets the bounding_polygon of this KeyValueSelectionEntity.

        :return: The bounding_polygon of this KeyValueSelectionEntity.
        :rtype: oci.data_labeling_service_dataplane.models.BoundingPolygon
        """
        return self._bounding_polygon

    @bounding_polygon.setter
    def bounding_polygon(self, bounding_polygon):
        """
        Sets the bounding_polygon of this KeyValueSelectionEntity.

        :param bounding_polygon: The bounding_polygon of this KeyValueSelectionEntity.
        :type: oci.data_labeling_service_dataplane.models.BoundingPolygon
        """
        self._bounding_polygon = bounding_polygon

    @property
    def rotation(self):
        """
        Gets the rotation of this KeyValueSelectionEntity.
        Integer value.


        :return: The rotation of this KeyValueSelectionEntity.
        :rtype: float
        """
        return self._rotation

    @rotation.setter
    def rotation(self, rotation):
        """
        Sets the rotation of this KeyValueSelectionEntity.
        Integer value.


        :param rotation: The rotation of this KeyValueSelectionEntity.
        :type: float
        """
        self._rotation = rotation

    @property
    def confidence(self):
        """
        **[Required]** Gets the confidence of this KeyValueSelectionEntity.
        float value, score from OCR.


        :return: The confidence of this KeyValueSelectionEntity.
        :rtype: float
        """
        return self._confidence

    @confidence.setter
    def confidence(self, confidence):
        """
        Sets the confidence of this KeyValueSelectionEntity.
        float value, score from OCR.


        :param confidence: The confidence of this KeyValueSelectionEntity.
        :type: float
        """
        self._confidence = confidence

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
