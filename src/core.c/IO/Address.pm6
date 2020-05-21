role IO::Address {
    has Mu $!VM-address is required;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}

    method family(::?CLASS:D: --> ProtocolFamily:D) {
        ProtocolFamily(nqp::p6box_i(nqp::addrfamily($!VM-address)))
    }

    method type(::?CLASS:D: --> SocketType:D) {
        SocketType(nqp::p6box_i(nqp::addrtype($!VM-address)))
    }

    method protocol(::?CLASS:D: --> ProtocolType:D) {
        ProtocolType(nqp::p6box_i(nqp::addrprotocol($!VM-address)))
    }

    multi method gist(::?CLASS:D: --> Str:D) {
        nqp::p6box_s(nqp::addrtopres($!VM-address))
    }
}

class IO::Address::UNIX does IO::Address {
    multi method new(
        ::?CLASS:_:
        IO::Path:D      $path,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), self.WHAT, '$!VM-address', nqp::addrfrompath(
            nqp::unbox_s($path.Str), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
    }
    multi method new(
        ::?CLASS:_:
        Str:D           $path,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), self.WHAT, '$!VM-address', nqp::addrfrompath(
            nqp::decont_s($path), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
    }
}

role IO::Address::IP does IO::Address {
    # XXX: $!VM-address is considered not to be an attribute of this role.
    # This is technically true, but it means duplicating this method...
    method port(::?CLASS:D: --> Int:D) { ... }
}

class IO::Address::IPv4 does IO::Address::IP {
    multi method new(
        ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), self.WHAT, '$!VM-address', nqp::addrfromipv4(
            nqp::decont_s($ip), nqp::decont_i($port),
            nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)))
    }

    method port(::?CLASS:D: --> Int:D) {
        nqp::p6box_i(nqp::addrport($!VM-address))
    }
}

class IO::Address::IPv6 does IO::Address::IP {
    multi method new(
        ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port,
        UInt:D         :$flowinfo = 0,
        UInt:D         :$scope-id = 0,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), self.WHAT, '$!VM-address', nqp::addrfromipv6(
            nqp::decont_s($ip), nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id),
            nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)))
    }

    method port(::?CLASS:D: --> Int:D) {
        nqp::p6box_i(nqp::addrport($!VM-address))
    }

    method flowinfo(::?CLASS:D: --> Int:D) {
        nqp::p6box_i(nqp::addrflowinfo($!VM-address))
    }

    method scope-id(::?CLASS:D: --> Int:D) {
        nqp::p6box_i(nqp::addrscopeid($!VM-address))
    }
}
