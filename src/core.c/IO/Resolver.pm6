class IO::Resolver {
    method resolve(
        ::?CLASS:_:
        Str:D             $host,
        Int:D             $port,
        ProtocolFamily:D :$family   = PF_UNSPEC,
        SocketType:D     :$type     = SOCK_STREAM,
        ProtocolType:D   :$protocol = IPPROTO_TCP,
        Bool:D           :$passive  = True,
        --> Iterable:D
    ) {
        gather {
            my @addresses := nqp::hllize(nqp::getaddrinfo(
                nqp::decont_s($host), nqp::decont_i($port),
                nqp::unbox_i($family.Int), nqp::unbox_i($type.Int), nqp::unbox_i($protocol.Int),
                nqp::unbox_i($passive.Int)));
            for @addresses {
                my Mu \T = do given nqp::p6box_i(nqp::addrfamily($_)) {
                    when PF_INET  { IO::Address::IPv4 }
                    when PF_INET6 { IO::Address::IPv6 }
                    when PF_UNIX  { IO::Address::UNIX } # Should never happen.
                    default       { IO::Address.^pun  } # Ditto.
                };
                my $address := nqp::create(T);
                nqp::bindattr($address, T, '$!VM-address', $_);
                take $address;
            }
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
