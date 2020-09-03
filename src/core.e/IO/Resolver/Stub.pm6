my class IO::Resolver::Stub is IO::Resolver {
    my constant Port = IO::Address::IP::Port;

    has Mu $!VM-resolver is required;

    submethod BUILD(::?CLASS:D: :@name-servers where .all ~~ IO::Address::IP:D, Port :$port = 53 --> Nil) {
        my Mu $name-servers := nqp::list;
        nqp::push($name-servers, nqp::getattr(nqp::decont($_), IO::Address, '$!VM-address')) for @name-servers;
        $!VM-resolver := nqp::dnsresolver($name-servers, nqp::decont_i($port), blob8.^pun);
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver::Stub.new;
}, '6.e';
