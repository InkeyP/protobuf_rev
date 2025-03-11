from pwn import *
from enum import Enum, Flag
import struct
import sys, os


def read_string(filename, offset, encoding='utf-8'):
    elf = ELF(filename)
    result = bytearray()
    while True:
        byte = elf.read(offset, 1)
        if not byte or byte == b'\x00':
            break
        result.extend(byte)
        offset += 1
    return result.decode(encoding)


class ProtobufCFieldFlag(Flag):
    PROTOBUF_C_FIELD_FLAG_PACKED = 1 << 0  # Set if the field is repeated and marked with the `packed` option.
    PROTOBUF_C_FIELD_FLAG_DEPRECATED = 1 << 1  # Set if the field is marked with the `deprecated` option.
    PROTOBUF_C_FIELD_FLAG_ONEOF = 1 << 2  # Set if the field is a member of a oneof (union).


class ProtobufCLabel(Enum):
    '''
    A well-formed message must have exactly one of this field.
    '''
    PROTOBUF_C_LABEL_REQUIRED = 0
    '''
    A well-formed message can have zero or one of this field (but not more than one).
	'''
    PROTOBUF_C_LABEL_OPTIONAL = 1
    '''
    This field can be repeated any number of times (including zero) in a
    well-formed message. The order of the repeated values will be preserved.
    '''
    PROTOBUF_C_LABEL_REPEATED = 2
    '''
    This field has no label. This is valid only in proto3 and is
	equivalent to OPTIONAL but no "has" quantifier will be consulted.
    '''
    PROTOBUF_C_LABEL_NONE = 3


class ProtobufCLabel(Enum):
    PROTOBUF_C_LABEL_REQUIRED = 0  # A well-formed message must have exactly one of this field.
    PROTOBUF_C_LABEL_OPTIONAL = 1  # A well-formed message can have zero or one of this field (but not more than one).
    PROTOBUF_C_LABEL_REPEATED = 2  # This field can be repeated any number of times (including zero) in a well-formed message. The order of the repeated values will be preserved.
    PROTOBUF_C_LABEL_NONE = 3  # This field has no label. This is valid only in proto3 and is equivalent to OPTIONAL but no "has" quantifier will be consulted.


label_mapping = {
    'PROTOBUF_C_LABEL_REQUIRED': 'required',
    'PROTOBUF_C_LABEL_OPTIONAL': 'optional',
    'PROTOBUF_C_LABEL_REPEATED': 'repeated',
    'PROTOBUF_C_LABEL_NONE': '',
}


class ProtobufCType(Enum):
    PROTOBUF_C_TYPE_INT32 = 0  # int32
    PROTOBUF_C_TYPE_SINT32 = 1  # signed int32
    PROTOBUF_C_TYPE_SFIXED32 = 2  # signed int32 (4 bytes)
    PROTOBUF_C_TYPE_INT64 = 3  # int64
    PROTOBUF_C_TYPE_SINT64 = 4  # signed int64
    PROTOBUF_C_TYPE_SFIXED64 = 5  # signed int64 (8 bytes)
    PROTOBUF_C_TYPE_UINT32 = 6  # unsigned int32
    PROTOBUF_C_TYPE_FIXED32 = 7  # unsigned int32 (4 bytes)
    PROTOBUF_C_TYPE_UINT64 = 8  # unsigned int64
    PROTOBUF_C_TYPE_FIXED64 = 9  # unsigned int64 (8 bytes)
    PROTOBUF_C_TYPE_FLOAT = 10  # float
    PROTOBUF_C_TYPE_DOUBLE = 11  # double
    PROTOBUF_C_TYPE_BOOL = 12  # boolean
    PROTOBUF_C_TYPE_ENUM = 13  # enumerated type
    PROTOBUF_C_TYPE_STRING = 14  # UTF-8 or ASCII string
    PROTOBUF_C_TYPE_BYTES = 15  # arbitrary byte sequence
    PROTOBUF_C_TYPE_MESSAGE = 16  # nested message


type_mapping = {
    'PROTOBUF_C_TYPE_INT32': 'int32',  # int32
    'PROTOBUF_C_TYPE_SINT32': 'sint32',  # signed int32
    'PROTOBUF_C_TYPE_SFIXED32': 'sfixed32',  # signed int32 (4 bytes)
    'PROTOBUF_C_TYPE_INT64': 'int64',  # int64
    'PROTOBUF_C_TYPE_SINT64': 'sint64',  # signed int64
    'PROTOBUF_C_TYPE_SFIXED64': 'sfixed64',  # signed int64 (8 bytes)
    'PROTOBUF_C_TYPE_UINT32': 'uint32',  # unsigned int32
    'PROTOBUF_C_TYPE_FIXED32': 'fixed32',  # unsigned int32 (4 bytes)
    'PROTOBUF_C_TYPE_UINT64': 'uint64',  # unsigned int64
    'PROTOBUF_C_TYPE_FIXED64': 'fixed64',  # unsigned int64 (8 bytes)
    'PROTOBUF_C_TYPE_FLOAT': 'float',  # float
    'PROTOBUF_C_TYPE_DOUBLE': 'double',  # double
    'PROTOBUF_C_TYPE_BOOL': 'bool',  # boolean
    'PROTOBUF_C_TYPE_ENUM': 'enum',  # enumerated type
    'PROTOBUF_C_TYPE_STRING': 'string',  # UTF-8 or ASCII string
    'PROTOBUF_C_TYPE_BYTES': 'bytes',  # arbitrary byte sequence
    'PROTOBUF_C_TYPE_MESSAGE': 'message',  # nested message
}


class ProtobufCMessageDescriptor:
    def __init__(self, data, filename):
        attr_names = [
            'magic', 'name', 'short_name', 'c_name', 'package_name', 'nop',
            'n_values', 'values', 'n_value_names', 'values_by_name',
            'n_value_ranges', 'value_ranges', 'reserved1', 'reserved2',
            'reserved3', 'reserved4'
        ]
        for name, value in zip(attr_names, struct.unpack("PPPPPQQPIPIPPPPP", data.ljust(0x80, b'\x00'))):
            setattr(self, name, value)

        self.filename = filename
        self.elf = ELF(self.filename)
        self.name = read_string(self.filename, self.name)
        self.short_name = read_string(self.filename, self.short_name)
        self.c_name = read_string(self.filename, self.c_name)
        self.package_name = read_string(self.filename, self.package_name)

        self.values_struct = [None] * self.n_values
        offset = self.values - 0x48
        for i in range(self.n_values):
            self.values_struct[i] = ProtobufCFieldDescriptor(self.elf.read(offset := offset + 0x48, 0x48), self.filename)


class ProtobufCFieldDescriptor:
    def __init__(self, data, filename):
        attr_names = [
            'name', 'id', 'label', 'type', 'quantifier_offset',
            'offset', 'descriptor', 'default_value', 'flags',
            'reserved_flags', 'reserved2', 'reserved3'
        ]
        for name, value in zip(attr_names, struct.unpack("PIIIIIPPIIPP", data)):
            setattr(self, name, value)

        self.filename = filename
        self.name = read_string(self.filename, self.name)


class Protobuf_rev:
    def __init__(self, filename):
        self.filename = filename

        with open(self.filename, 'rb') as f:
            data = f.read()
        offset_ProtobufCMessageDescriptor = data.find(b'\xF9\xEE\xAA\x28\x00\x00\x00\x00')
        assert offset_ProtobufCMessageDescriptor != -1
        self.ProtobufCMessageDescriptor = ProtobufCMessageDescriptor(data[offset_ProtobufCMessageDescriptor:offset_ProtobufCMessageDescriptor + 0x78],
                                                                     self.filename)

    def __str__(self):
        output = f'''package_name: {self.ProtobufCMessageDescriptor.package_name}
name: {self.ProtobufCMessageDescriptor.name}
counts of values: {self.ProtobufCMessageDescriptor.n_values}
'''
        for i in range(self.ProtobufCMessageDescriptor.n_values):
            output += f'''
value[{i}]:
    name: {self.ProtobufCMessageDescriptor.values_struct[i].name}
    id: {self.ProtobufCMessageDescriptor.values_struct[i].id}
    type: {ProtobufCType(self.ProtobufCMessageDescriptor.values_struct[i].type).name}
    label: {ProtobufCLabel(self.ProtobufCMessageDescriptor.values_struct[i].label).name}
'''
        return output

    def gen_proto(self):
        output = f'''syntax = "proto3";

package {self.ProtobufCMessageDescriptor.package_name if self.ProtobufCMessageDescriptor.package_name else self.ProtobufCMessageDescriptor.name};

message {self.ProtobufCMessageDescriptor.short_name} {{
'''
        for i in range(self.ProtobufCMessageDescriptor.n_values):
            output += f'    {label_mapping[ProtobufCLabel(self.ProtobufCMessageDescriptor.values_struct[i].label).name]} {type_mapping[ProtobufCType(self.ProtobufCMessageDescriptor.values_struct[i].type).name]} {self.ProtobufCMessageDescriptor.values_struct[i].name} = {self.ProtobufCMessageDescriptor.values_struct[i].id};\n'
        output += '}\n'
        return output


if __name__ == '__main__':
    filename = sys.argv[1]
    p = Protobuf_rev(filename)
    print(p)
    with open('ctf.proto', 'w') as f:
        f.write(p.gen_proto())
    os.system("protoc --python_out=./ ./ctf.proto")
