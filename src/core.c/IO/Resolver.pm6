class IO::Resolver {
    method resolve(
        ::?CLASS:D:
        Str:D             $host,
        Int:D             $port,
        ProtocolFamily:D :$family   = PF_UNSPEC,
        SocketType:D     :$type     = SOCK_STREAM,
        ProtocolType:D   :$protocol = IPPROTO_TCP,
        Bool:D           :$passive  = True,
        --> Iterable:D
    ) {
        gather for nqp::hllize(nqp::getaddrinfo(
            nqp::decont_s($host), nqp::decont_i($port),
            nqp::unbox_i($family.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int),
            nqp::unbox_i($passive.Int)))
            -> (Mu $VM-address is raw, Int:D $family, Int:D $type, Int:D $protocol)
        {
            my Mu \A = do given $family {
                when PF_INET  { IO::Address::IPv4 }
                when PF_INET6 { IO::Address::IPv6 }
                when PF_UNIX  { IO::Address::UNIX } # Should never happen.
                default       { IO::Address.^pun  } # Ditto.
            };
            my $address := nqp::p6bindattrinvres(nqp::create(A), A, '$!VM-address', $VM-address);
            nqp::bindattr($address, A, '$!type', SocketType($type));
            nqp::bindattr($address, A, '$!protocol', ProtocolType($type));
            take $address;
        }
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver.new;
};

Rakudo::Internals.REGISTER-DYNAMIC: '&*CONNECT', {
    PROCESS::<&CONNECT> := sub CONNECT(Iterable:D $addresses is raw, &callback --> Mu) {
        callback $addresses.head
    };
};
