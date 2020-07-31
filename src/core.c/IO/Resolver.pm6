my class IO::Resolver {
    my constant Port = IO::Address::IP::Port;

    method resolve(
        ::?CLASS:D:
        Str:_             $hostname,
        Port              $port      = 0,
        SocketFamily:D   :$family    = PF_UNSPEC,
        SocketType:D     :$type      = SOCK_ANY,
        SocketProtocol:D :$protocol  = IPPROTO_ANY,
        Bool:D           :$passive   = False,
        --> Supply:D
    ) {
        supply for nqp::hllize(nqp::dnsresolve(
          (my str $ = $hostname // nqp::null_s), nqp::decont_i($port),
          nqp::unbox_i($family.value), nqp::unbox_i($type.value), nqp::unbox_i($protocol.value),
          nqp::unbox_i($passive.Int)
        )) -> [
            Int:D $address-family is raw,
            Mu    $VM-address     is raw,
            Int:D $family         is raw,
            Int:D $type           is raw,
            Int:D $protocol       is raw,
        ] {
            my IO::Address:U \T = IO::Address[SocketFamily($address-family)];
            emit IO::Address::Info.new:
                nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address),
                family   => SocketFamily($family),
                type     => SocketType($type),
                protocol => SocketProtocol($protocol);
        }
    }

    method lookup(::?CLASS:D: |args --> Supply:D) {
        self.resolve: |args
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver.new;
};
