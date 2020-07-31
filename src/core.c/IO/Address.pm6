my class IO::Address {
    has Mu $!VM-address is required;

    method family(::?CLASS:_: --> SocketFamily:D) { ... }

    # Subtypes of IO::Address may work with one and only one family of address.
    # When this is the case, it should be registered as a specialization of
    # IO::Address for said family. These metamethods manage IO::Address' state
    # for specializations:
    my ::?CLASS:U %specializations{SocketFamily:D};
    method ^has_family_specialization(
        ::?CLASS:U,
        SocketFamily:D $family is raw,
        --> Bool:D
    ) is implementation-detail {
        %specializations{$family}:exists
    }
    method ^get_family_specialization(
        ::?CLASS:U,
        SocketFamily:D $family is raw,
        --> Mu
    ) is implementation-detail {
        %specializations{$family}
    }
    method ^set_family_specialization(
        ::?CLASS:U,
        SocketFamily:D $family is raw,
        ::?CLASS:U       $mixin  is raw,
        --> ::?CLASS:U
    ) is implementation-detail {
        %specializations{$family} := $mixin
    }

    # IO::Address, when parameterized with an address family, should always
    # return a type that knows how to handle addresses of that family best.
    # The key here is a type must exist for *all* families, as support for more
    # families may exist in the future, but we may only know enough about them
    # to make I/O syscalls with them. Therefore, if a specialization of
    # IO::Address for the given family exists, then it should be returned,
    # otherwise we should generate an IO::Address mixin that at least knows
    # what family of address it belongs to:
    my role WithFamily[SocketFamily:D $family is raw] {
        method family(::?CLASS:_: --> SocketFamily:D) { $family }
    }
    method ^parameterize(::?CLASS:U $this is raw, SocketFamily:D $family --> ::?CLASS:U) {
        if self.has_family_specialization: $this, $family {
            self.get_family_specialization: $this, $family
        }
        else {
            my Mu $mixin := self.mixin: $this, WithFamily.^parameterize: nqp::decont($family);
            $mixin.^set_name: self.name($this) ~ '[' ~ $family ~ ']';
            $mixin
        }
    }
}

my class IO::Address::IP is IO::Address is Cool {
    has Int:_ $!numeric;

    subset Port of Int:D where 0x0000..0xFFFF;
    method port(::?CLASS:D: --> Port) {
        nqp::addrport(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

    method literal(::?CLASS:D: --> Str:D) {
        nqp::addrtostr(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

    multi method Str(::?CLASS:D: --> Str:D) { self.literal }

    multi method Stringy(::?CLASS:D: --> Str:D) { self.literal }

    method raw(::?CLASS:D: Blob:U \T = blob8 --> Blob:D) {
        nqp::addrtobuf(nqp::getattr(self, IO::Address, '$!VM-address'), T.^pun)
    }

    multi method Int(::?CLASS:D: --> Int:D) {
        $!numeric // ($!numeric := self.raw(blob32).contents.reduce(* +< 32 +| *))
    }

    multi method Numeric(::?CLASS:D: --> Numeric:D) { self.Int }
}

my class IO::Address::IPv4 is IO::Address::IP {
    my constant Port = IO::Address::IP::Port;

    subset Range of Int:D where ^1 +< 33;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}
    multi method new(::?CLASS:_: Str:D $literal, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfromstr_ip4(nqp::decont_s($literal), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: Blob:D $raw, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfrombuf_ip4(nqp::decont($raw), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: ::Range $numeric, |rest --> ::?CLASS:D) {
        samewith blob32.new($numeric), |rest
    }

    method family(::?CLASS:_: --> PF_INET) { }

    # RFC 6890 section 2.2.2: IPv4 Special-Purpose Address Registry Entries
    method is-unspecified(::?CLASS:D: --> Bool:D) { self +> 24 == 0 }
    method is-loopback(::?CLASS:D: --> Bool:D)    { self +> 24 == 0x7F }
    method is-broadcast(::?CLASS:D: --> Bool:D)   { self == 0xFFFFFFFF }
    method is-private(::?CLASS:D: --> Bool:D)     { self +> 24 == 0x0A || self +> 20 == 0x0AC1 || self +> 16 == 0xC0A8 }
    method is-shared(::?CLASS:D: --> Bool:D)      { self +> 22 == 0x0191 }
    method is-link-local(::?CLASS:D: --> Bool:D)  { self +> 16 == 0xA9FE }

    multi method gist(::?CLASS:D: --> Str:D) { "$.literal:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Str:D $raku = "$.^name\.new($.literal.raku()";
        my Int:D $port = self.port;
        $raku ~= ", $port.raku()" if $port;
        $raku ~= ')';
        $raku
    }
}

my class IO::Address::IPv6 is IO::Address::IP {
    my constant Port = IO::Address::IP::Port;

    subset Range of Int:D where ^1 +< 129;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}
    multi method new(::?CLASS:_: Str:D $literal, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfromstr_ip6(nqp::decont_s($literal), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: Blob:D $raw, Port $port = 0, UInt:D :$scope-id = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfrombuf_ip6(nqp::decont($raw), nqp::decont_i($port), nqp::decont_i($scope-id)))
    }
    multi method new(::?CLASS:_: ::Range $numeric, |rest --> ::?CLASS:D) {
        samewith blob64.new($numeric +> 64, $numeric +& 0xFFFFFFFFFFFFFFFF), |rest
    }

    method family(::?CLASS:_: --> PF_INET6) { }

    method scope-id(::?CLASS:D: --> Int:D) {
        nqp::addrscopeid(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

    # RFC 6890 section 2.2.3: IPv6 Special-Purpose Address Registry Entries
    method is-unspecified(::?CLASS:D: --> Bool:D)         { self == 0 }
    method is-loopback(::?CLASS:D: --> Bool:D)            { self == 1 }
    method is-ipv4-compatible(::?CLASS:D: --> Bool:D)     { self +> 32 == 0x0000 }
    method is-ipv4-mapped(::?CLASS:D: --> Bool:D)         { self +> 32 == 0xFFFF }
    method is-ipv4-encapsulatable(::?CLASS:D: --> Bool:D) { self +> 112 == 0x2002 } # i.e. 6to4

    # RFC 4291 section 2.4: Address Type Identification
    method is-multicast(::?CLASS:D: --> Bool:D) { self +> 120 == 0xFF }
    method is-unicast(::?CLASS:D: --> Bool:D)   { self +> 120 != 0xFF }

    subset Scope of Int:D where 0x0..0xF;
    method scope(::?CLASS:D: --> Scope) {
        # RFC 4291 section 2.7: Multicast Addresses
        self +> 120 == 0xFF
          ?? self +> 112 +& 0xF
          # RFC 4291 section 2.5.6: Link-Local IPv6 Unicast Addresses
          !! self +> 118 == 0x03FA
            ?? 0x2
            # RFC 4291 section 2.5.7: Site-Local IPv6 Unicast Addresses
            !! self +> 118 == 0x03FB
              ?? 0x5
              # RFC 4291 section 2.4: Address Type Identification
              !! 0xE
    }

    # RFC 7346 section 2: Definition of IPv6 Multicast Address Scopes
    method is-interface-local(::?CLASS:D: --> Bool:D)    { self.scope == 0x1 }
    method is-link-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x2 }
    method is-realm-local(::?CLASS:D: --> Bool:D)        { self.scope == 0x3 }
    method is-admin-local(::?CLASS:D: --> Bool:D)        { self.scope == 0x4 }
    method is-site-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x5 }
    method is-organization-local(::?CLASS:D: --> Bool:D) { self.scope == 0x8 }
    method is-global(::?CLASS:D: --> Bool:D)             { self.scope == 0xE }

    multi method gist(::?CLASS:D: --> Str:D) { "[$.literal]:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Str:D $raku = "$.^name\.new($.literal.raku()";
        my Int:D $port = self.port;
        $raku ~= ", $port.raku()" if $port;
        $raku ~= ')';
        $raku
    }
}

my class IO::Address::UNIX is IO::Address {
    has Bool:D $!raw is required;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}
    multi method new(::?CLASS:_: IO::Path:D $path --> ::?CLASS:D) {
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, IO::Address, '$!VM-address', nqp::addrfromstr_un(nqp::unbox_s(~$path)));
        nqp::bindattr($self, IO::Address::UNIX, '$!raw', False);
        $self
    }
    multi method new(::?CLASS:_: Blob:D $raw --> ::?CLASS:D) {
        my ::?CLASS:D $self := nqp::create(self);
        nqp::bindattr($self, IO::Address, '$!VM-address', nqp::addrfrombuf_un(nqp::decont($raw)));
        nqp::bindattr($self, IO::Address::UNIX, '$!raw', True);
        $self
    }

    method family(::?CLASS:_: --> PF_UNIX) { }

    multi method Str(::?CLASS:D: --> Str:D) {
        nqp::addrtostr(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

    multi method Stringy(::?CLASS:D: --> Str:D) {
        nqp::addrtostr(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

    method path(::?CLASS:D: --> IO::Path:D) { IO::Path.new: self.Str }
    method IO(::?CLASS:D: --> IO:D)         { self.path }

    method raw(::?CLASS:D: --> Blob:D) {
        nqp::addrtobuf(nqp::getattr(self, IO::Address, '$!VM-address'), Blob[int8].^pun)
    }

    multi method gist(::?CLASS:D: --> Str:D) {
        $!raw
            ?? self.Str.encode.decode.subst(/ \x[10FFFD] x ( <[ 0..9 A..F ]> ** 2 ) /, { "%$0" }, :g)
            !! self.Str
    }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Str:D $raku = "$.^name\.new(";
        $raku ~= $!raw ?? self.raw.raku !! self.path.raku;
        $raku ~= ')';
        $raku
    }
}

BEGIN {
    IO::Address.^set_family_specialization: PF_INET, IO::Address::IPv4;
    IO::Address.^set_family_specialization: PF_INET6, IO::Address::IPv6;
    IO::Address.^set_family_specialization: PF_UNIX, IO::Address::UNIX;
}

my class IO::Address::Info {
    has IO::Address:D    $.address  is required;
    has SocketFamily:D   $.family   is required;
    has SocketType:D     $.type     is required;
    has SocketProtocol:D $.protocol is required;

    method new(::?CLASS:_: IO::Address:D $address, *%rest --> ::?CLASS:D) {
        self.bless: :$address, |%rest
    }

    multi method gist(::?CLASS:D: --> Str:D) {
        "$!address.gist()+<$!family $!type $!protocol>"
    }
}
