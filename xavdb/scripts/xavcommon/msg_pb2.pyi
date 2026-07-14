from xavcommon import scan_status_pb2 as _scan_status_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Message(_message.Message):
    __slots__ = ["scan_status"]
    SCAN_STATUS_FIELD_NUMBER: _ClassVar[int]
    scan_status: _scan_status_pb2.ScanStatus
    def __init__(self, scan_status: _Optional[_Union[_scan_status_pb2.ScanStatus, _Mapping]] = ...) -> None: ...
