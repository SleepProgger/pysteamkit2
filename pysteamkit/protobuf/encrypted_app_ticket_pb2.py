# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: encrypted_app_ticket.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='encrypted_app_ticket.proto',
  package='',
  serialized_pb=_b('\n\x1a\x65ncrypted_app_ticket.proto\"\xad\x01\n\x12\x45ncryptedAppTicket\x12\x19\n\x11ticket_version_no\x18\x01 \x01(\r\x12\x1b\n\x13\x63rc_encryptedticket\x18\x02 \x01(\r\x12\x1c\n\x14\x63\x62_encrypteduserdata\x18\x03 \x01(\r\x12\'\n\x1f\x63\x62_encrypted_appownershipticket\x18\x04 \x01(\r\x12\x18\n\x10\x65ncrypted_ticket\x18\x05 \x01(\x0c\x42\x05H\x01\x80\x01\x00')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_ENCRYPTEDAPPTICKET = _descriptor.Descriptor(
  name='EncryptedAppTicket',
  full_name='EncryptedAppTicket',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ticket_version_no', full_name='EncryptedAppTicket.ticket_version_no', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='crc_encryptedticket', full_name='EncryptedAppTicket.crc_encryptedticket', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cb_encrypteduserdata', full_name='EncryptedAppTicket.cb_encrypteduserdata', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cb_encrypted_appownershipticket', full_name='EncryptedAppTicket.cb_encrypted_appownershipticket', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='encrypted_ticket', full_name='EncryptedAppTicket.encrypted_ticket', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=31,
  serialized_end=204,
)

DESCRIPTOR.message_types_by_name['EncryptedAppTicket'] = _ENCRYPTEDAPPTICKET

EncryptedAppTicket = _reflection.GeneratedProtocolMessageType('EncryptedAppTicket', (_message.Message,), dict(
  DESCRIPTOR = _ENCRYPTEDAPPTICKET,
  __module__ = 'encrypted_app_ticket_pb2'
  # @@protoc_insertion_point(class_scope:EncryptedAppTicket)
  ))
_sym_db.RegisterMessage(EncryptedAppTicket)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('H\001\200\001\000'))
# @@protoc_insertion_point(module_scope)
