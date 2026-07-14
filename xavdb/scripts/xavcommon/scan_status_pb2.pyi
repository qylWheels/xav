from xavcommon import malware_info_pb2 as _malware_info_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
Paused: ScanStatusEnum
Scanning: ScanStatusEnum
Stopped: ScanStatusEnum

class ScanStatus(_message.Message):
    __slots__ = ["curr_scanning_file", "malware_infos", "scan_status", "scanned_file_count", "total_file_count"]
    CURR_SCANNING_FILE_FIELD_NUMBER: _ClassVar[int]
    MALWARE_INFOS_FIELD_NUMBER: _ClassVar[int]
    SCANNED_FILE_COUNT_FIELD_NUMBER: _ClassVar[int]
    SCAN_STATUS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FILE_COUNT_FIELD_NUMBER: _ClassVar[int]
    curr_scanning_file: str
    malware_infos: _containers.RepeatedCompositeFieldContainer[_malware_info_pb2.MalwareInfo]
    scan_status: ScanStatusEnum
    scanned_file_count: int
    total_file_count: int
    def __init__(self, scan_status: _Optional[_Union[ScanStatusEnum, str]] = ..., total_file_count: _Optional[int] = ..., scanned_file_count: _Optional[int] = ..., malware_infos: _Optional[_Iterable[_Union[_malware_info_pb2.MalwareInfo, _Mapping]]] = ..., curr_scanning_file: _Optional[str] = ...) -> None: ...

class ScanStatusEnum(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
