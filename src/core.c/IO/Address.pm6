role IO::Address {
    has Mu $!VM-address is required;

    method family(::?CLASS:D: --> ProtocolFamily:D) {
        ProtocolFamily(
            nqp::p6box_i(nqp::addrfamily($!VM-address)))
    }

    method type(::?CLASS:D: --> SocketType:D) {
        SocketType(
            nqp::p6box_i(nqp::addrtype($!VM-address)))
    }

    method protocol(::?CLASS:D: --> ProtocolType:D) {
        ProtocolType(
            nqp::p6box_i(nqp::addrprotocol($!VM-address)))
    }
}

class IO::Address::UNIX does IO::Address {
    method gist(::?CLASS:D: --> '?') { }
}

role IO::Address::IP does IO::Address { }

class IO::Address::IPv4 does IO::Address::IP {
    method gist(::?CLASS:D: --> '?.?.?.?') { }
}

class IO::Address::IPv6 does IO::Address::IP {
    method gist(::?CLASS:D: --> '?:?:?:?:?:?:?:?') { }
}
