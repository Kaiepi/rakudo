my role IO {
    # This role is empty and exists so that IO() coercers
    # that coerce to IO::Path type check the result values OK
}

enum SeekType (
  :SeekFromBeginning(0),
  :SeekFromCurrent(1),
  :SeekFromEnd(2),
);

enum SocketFamily (
  :PF_UNSPEC(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNSPEC)),
  :PF_INET(nqp::p6box_i(nqp::const::SOCKET_FAMILY_INET)),
  :PF_INET6(nqp::p6box_i(nqp::const::SOCKET_FAMILY_INET6)),
  :PF_LOCAL(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNIX)),
  :PF_UNIX(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNIX)),
);

my Enumeration:U constant ProtocolFamily = SocketFamily;

enum SocketType (
  :SOCK_ANY(nqp::p6box_i(nqp::const::SOCKET_TYPE_ANY)),
  :SOCK_STREAM(nqp::p6box_i(nqp::const::SOCKET_TYPE_STREAM)),
  :SOCK_DGRAM(nqp::p6box_i(nqp::const::SOCKET_TYPE_DGRAM)),
  :SOCK_RAW(nqp::p6box_i(nqp::const::SOCKET_TYPE_RAW)),
  :SOCK_RDM(nqp::p6box_i(nqp::const::SOCKET_TYPE_RDM)),
  :SOCK_SEQPACKET(nqp::p6box_i(nqp::const::SOCKET_TYPE_SEQPACKET)),
);

enum SocketProtocol (
  :IPPROTO_ANY(nqp::p6box_i(nqp::const::SOCKET_PROTOCOL_ANY)),
  :IPPROTO_TCP(nqp::p6box_i(nqp::const::SOCKET_PROTOCOL_TCP)),
  :IPPROTO_UDP(nqp::p6box_i(nqp::const::SOCKET_PROTOCOL_UDP)),
);

my Enumeration:U    constant ProtocolType = SocketProtocol;
my SocketProtocol:D constant PROTO_TCP    = IPPROTO_TCP;
my SocketProtocol:D constant PROTO_UDP    = IPPROTO_UDP;

# vim: expandtab shiftwidth=4
