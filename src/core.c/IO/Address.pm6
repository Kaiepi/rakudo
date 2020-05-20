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
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, self.WHAT, '$!VM-address', nqp::addrfrompres(
            nqp::unbox_s($path.Str), 0,
            nqp::unbox_i(PF_UNIX.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
        $self
    }
    multi method new(
        ::?CLASS:_:
        Str:D           $path,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, self.WHAT, '$!VM-address', nqp::addrfrompres(
            nqp::decont_s($path), 0,
            nqp::unbox_i(PF_UNIX.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
        $self
    }

}

role IO::Address::IP does IO::Address { }

class IO::Address::IPv4 does IO::Address::IP {
    multi method new(
        ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, self.WHAT, '$!VM-address', nqp::addrfrompres(
            nqp::decont_s($ip), nqp::decont_i($port),
            nqp::unbox_i(PF_INET.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
        $self
    }
}

class IO::Address::IPv6 does IO::Address::IP {
    multi method new(
        ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port,
        SocketType:D   :$type     = SOCK_STREAM,
        ProtocolType:D :$protocol = IPPROTO_TCP
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, self.WHAT, '$!VM-address', nqp::addrfrompres(
            nqp::decont_s($ip), nqp::decont_i($port),
            nqp::unbox_i(PF_INET6.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int)));
        $self
    }
}
