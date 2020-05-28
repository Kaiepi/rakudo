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
  :PF_UNSPEC(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNSPEC)),
  :PF_INET(nqp::p6box_i(nqp::const::SOCKET_FAMILY_INET)),
  :PF_INET6(nqp::p6box_i(nqp::const::SOCKET_FAMILY_INET6)),
  :PF_LOCAL(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNIX)),
  :PF_UNIX(nqp::p6box_i(nqp::const::SOCKET_FAMILY_UNIX)),
);

# TODO: These should be nqp constants.
enum SocketType (
  :SOCK_ANY(0),
  :SOCK_STREAM(1),
  :SOCK_DGRAM(2),
  :SOCK_RAW(3),
  :SOCK_RDM(4),
  :SOCK_SEQPACKET(5),
);

# TODO: These should be nqp constants.
# TODO: More protocols will be needed eventually, once support for socket
# options and raw sockets exists.
enum ProtocolType (
  :IPPROTO_ANY(0),
  :IPPROTO_TCP(1),
  :IPPROTO_UDP(2),
);

constant PROTO_TCP = IPPROTO_TCP;
constant PROTO_UDP = IPPROTO_UDP;

# vim: ft=perl6 expandtab sw=4
