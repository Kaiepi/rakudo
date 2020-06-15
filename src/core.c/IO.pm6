my role IO {
    # This role is empty and exists so that IO() coercers
    # that coerce to IO::Path type check the result values OK
}

enum SeekType (
  :SeekFromBeginning(0),
  :SeekFromCurrent(1),
  :SeekFromEnd(2),
);

enum ProtocolFamily (
  :PF_UNSPEC(nqp::p6box_i(nqp::const::ADDRESS_FAMILY_UNSPEC)),
  :PF_INET(nqp::p6box_i(nqp::const::ADDRESS_FAMILY_INET)),
  :PF_INET6(nqp::p6box_i(nqp::const::ADDRESS_FAMILY_INET6)),
  :PF_LOCAL(nqp::p6box_i(nqp::const::ADDRESS_FAMILY_UNIX)),
  :PF_UNIX(nqp::p6box_i(nqp::const::ADDRESS_FAMILY_UNIX)),
);

enum SocketType (
  :SOCK_ANY(nqp::p6box_i(nqp::const::ADDRESS_TYPE_ANY)),
  :SOCK_STREAM(nqp::p6box_i(nqp::const::ADDRESS_TYPE_STREAM)),
  :SOCK_DGRAM(nqp::p6box_i(nqp::const::ADDRESS_TYPE_DGRAM)),
  :SOCK_RAW(nqp::p6box_i(nqp::const::ADDRESS_TYPE_RAW)),
  :SOCK_RDM(nqp::p6box_i(nqp::const::ADDRESS_TYPE_RDM)),
  :SOCK_SEQPACKET(nqp::p6box_i(nqp::const::ADDRESS_TYPE_SEQPACKET)),
);

# TODO: More protocols will be needed eventually, once support for socket
# options and raw sockets exists.
enum ProtocolType (
  :IPPROTO_ANY(nqp::p6box_i(nqp::const::ADDRESS_PROTOCOL_ANY)),
  :IPPROTO_TCP(nqp::p6box_i(nqp::const::ADDRESS_PROTOCOL_TCP)),
  :IPPROTO_UDP(nqp::p6box_i(nqp::const::ADDRESS_PROTOCOL_UDP)),
);

constant PROTO_TCP = IPPROTO_TCP;
constant PROTO_UDP = IPPROTO_UDP;

# vim: ft=perl6 expandtab sw=4
