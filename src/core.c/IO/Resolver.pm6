my role X::IO::Resolver is Exception { }

my class X::IO::Resolver::Unreachable does X::IO::Resolver {
    has Str:_ $.host      is required;
    has Str:D $.operation is required;

    method message(::?CLASS:D: --> Str:D) {
        with $!host {
            "No addresses for host '$!host' were reachable when $!operation"
        } else {
            "No local addresses were reachable when $!operation"
        }
    }
}

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

Rakudo::Internals.REGISTER-DYNAMIC: '&*CONNECT', {
    PROCESS::<&CONNECT> := sub CONNECT(Str:_ $host, Supply:D $address-info, &connect-to --> Mu) is raw {
        for @$address-info -> IO::Address::Info:D $info {
            # Only attempt to connect to the first address, allowing exceptions
            # to be thrown.
            return-rw connect-to $info;
        }
        X::IO::Resolver::Unreachable.new(
            host      => $host,
            operation => 'connecting a socket',
        ).throw;
    };
};

Rakudo::Internals.REGISTER-DYNAMIC: '&*BIND', {
    PROCESS::<&BIND> := sub BIND(Str:_ $host, Supply:D $address-info, &bind-to --> Mu) is raw {
        for @$address-info -> IO::Address::Info:D $info {
            # Only attempt to bind to the first address, allowing exceptions to
            # be thrown.
            return-rw bind-to $info;
        }
        X::IO::Resolver::Unreachable.new(
            host      => $host,
            operation => 'binding a socket',
        ).throw;
    };
};

# vim: expandtab shiftwidth=4
