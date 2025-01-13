# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220125


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class VideoFaceFrame(object):
    """
    A face frame.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new VideoFaceFrame object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param time_offset_ms:
            The value to assign to the time_offset_ms property of this VideoFaceFrame.
        :type time_offset_ms: int

        :param confidence:
            The value to assign to the confidence property of this VideoFaceFrame.
        :type confidence: float

        :param quality_score:
            The value to assign to the quality_score property of this VideoFaceFrame.
        :type quality_score: float

        :param bounding_polygon:
            The value to assign to the bounding_polygon property of this VideoFaceFrame.
        :type bounding_polygon: oci.ai_vision.models.BoundingPolygon

        :param landmarks:
            The value to assign to the landmarks property of this VideoFaceFrame.
        :type landmarks: list[oci.ai_vision.models.Landmark]

        """
        self.swagger_types = {
            'time_offset_ms': 'int',
            'confidence': 'float',
            'quality_score': 'float',
            'bounding_polygon': 'BoundingPolygon',
            'landmarks': 'list[Landmark]'
        }

        self.attribute_map = {
            'time_offset_ms': 'timeOffsetMs',
            'confidence': 'confidence',
            'quality_score': 'qualityScore',
            'bounding_polygon': 'boundingPolygon',
            'landmarks': 'landmarks'
        }

        self._time_offset_ms = None
        self._confidence = None
        self._quality_score = None
        self._bounding_polygon = None
        self._landmarks = None

    @property
    def time_offset_ms(self):
        """
        **[Required]** Gets the time_offset_ms of this VideoFaceFrame.
        Time offset(Milliseconds) in the video.


        :return: The time_offset_ms of this VideoFaceFrame.
        :rtype: int
        """
        return self._time_offset_ms

    @time_offset_ms.setter
    def time_offset_ms(self, time_offset_ms):
        """
        Sets the time_offset_ms of this VideoFaceFrame.
        Time offset(Milliseconds) in the video.


        :param time_offset_ms: The time_offset_ms of this VideoFaceFrame.
        :type: int
        """
        self._time_offset_ms = time_offset_ms

    @property
    def confidence(self):
        """
        **[Required]** Gets the confidence of this VideoFaceFrame.
        The confidence score, between 0 and 1.


        :return: The confidence of this VideoFaceFrame.
        :rtype: float
        """
        return self._confidence

    @confidence.setter
    def confidence(self, confidence):
        """
        Sets the confidence of this VideoFaceFrame.
        The confidence score, between 0 and 1.


        :param confidence: The confidence of this VideoFaceFrame.
        :type: float
        """
        self._confidence = confidence

    @property
    def quality_score(self):
        """
        **[Required]** Gets the quality_score of this VideoFaceFrame.
        The quality score of the face detected, between 0 and 1.


        :return: The quality_score of this VideoFaceFrame.
        :rtype: float
        """
        return self._quality_score

    @quality_score.setter
    def quality_score(self, quality_score):
        """
        Sets the quality_score of this VideoFaceFrame.
        The quality score of the face detected, between 0 and 1.


        :param quality_score: The quality_score of this VideoFaceFrame.
        :type: float
        """
        self._quality_score = quality_score

    @property
    def bounding_polygon(self):
        """
        **[Required]** Gets the bounding_polygon of this VideoFaceFrame.

        :return: The bounding_polygon of this VideoFaceFrame.
        :rtype: oci.ai_vision.models.BoundingPolygon
        """
        return self._bounding_polygon

    @bounding_polygon.setter
    def bounding_polygon(self, bounding_polygon):
        """
        Sets the bounding_polygon of this VideoFaceFrame.

        :param bounding_polygon: The bounding_polygon of this VideoFaceFrame.
        :type: oci.ai_vision.models.BoundingPolygon
        """
        self._bounding_polygon = bounding_polygon

    @property
    def landmarks(self):
        """
        Gets the landmarks of this VideoFaceFrame.
        Face landmarks.


        :return: The landmarks of this VideoFaceFrame.
        :rtype: list[oci.ai_vision.models.Landmark]
        """
        return self._landmarks

    @landmarks.setter
    def landmarks(self, landmarks):
        """
        Sets the landmarks of this VideoFaceFrame.
        Face landmarks.


        :param landmarks: The landmarks of this VideoFaceFrame.
        :type: list[oci.ai_vision.models.Landmark]
        """
        self._landmarks = landmarks

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
