from xavcommon import scan_status_pb2 as _scan_status_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
ScanStatus: MessageType

class Message(_message.Message):
    __slots__ = ["scan_status", "type"]
    SCAN_STATUS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    scan_status: _scan_status_pb2.ScanStatus
    type: MessageType
    def __init__(self, type: _Optional[_Union[MessageType, str]] = ..., scan_status: _Optional[_Union[_scan_status_pb2.ScanStatus, _Mapping]] = ...) -> None: ...

class MessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
