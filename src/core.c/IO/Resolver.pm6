my class IO::Resolver {
    method resolve(
        ::?CLASS:D:
        Str:D             $host,
        Int:D             $port,
        ProtocolFamily:D :$family   = PF_UNSPEC,
        SocketType:D     :$type     = SOCK_ANY,
        ProtocolType:D   :$protocol = IPPROTO_ANY,
        Bool:D           :$passive  = True,
        --> Supply:D
    ) {
        supply for (
            nqp::hllize(nqp::getaddrinfo(
              nqp::decont_s($host), nqp::decont_i($port),
              nqp::unbox_i($family.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int),
              nqp::unbox_i($passive.Int)))
        ) -> (Mu $VM-address is raw, Int:D $family, Int:D $type, Int:D $protocol) {
            my Mu \A = do given $family {
                when PF_INET  { IO::Address::IPv4 }
                when PF_INET6 { IO::Address::IPv6 }
                when PF_UNIX  { IO::Address::UNIX } # Should never happen.
                default       { IO::Address.^pun  } # Ditto.
            };
            emit IO::Address::Info.new:
                nqp::p6bindattrinvres(nqp::create(A), A, '$!VM-address', $VM-address),
                type => SocketType($type), protocol => ProtocolType($protocol);
            LAST done;
        }
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver.new;
};

Rakudo::Internals.REGISTER-DYNAMIC: '&*CONNECT', {
    PROCESS::<&CONNECT> := sub CONNECT(Supply:D $addresses, &callback --> Mu) {
        callback await $addresses.head
    };
};
