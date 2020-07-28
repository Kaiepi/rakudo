my class IO::Address {
    has Mu $!VM-address is required;

    method family(::?CLASS:_: --> ProtocolFamily:D) { ... }

    # Subtypes of IO::Address may work with one and only one family of address.
    # When this is the case, it should be registered as a specialization of
    # IO::Address for said family. These metamethods manage IO::Address' state
    # for specializations:
    my ::?CLASS:U %specializations{ProtocolFamily:D};
    method ^has_family_specialization(
        ::?CLASS:U,
        ProtocolFamily:D $family is raw,
        --> Bool:D
    ) is implementation-detail {
        %specializations{$family}:exists
    }
    method ^get_family_specialization(
        ::?CLASS:U,
        ProtocolFamily:D $family is raw,
        --> Mu
    ) is implementation-detail {
        %specializations{$family}
    }
    method ^set_family_specialization(
        ::?CLASS:U,
        ProtocolFamily:D $family is raw,
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
    my role WithFamily[ProtocolFamily:D $family is raw] {
        method family(::?CLASS:_: --> ProtocolFamily:D) { $family }
    }
    method ^parameterize(::?CLASS:U $this is raw, ProtocolFamily:D $family --> ::?CLASS:U) {
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

my class IO::Address::IP is IO::Address {
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
}

my class IO::Address::IPv4 is IO::Address::IP {
    my constant Port = IO::Address::IP::Port;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}
    multi method new(::?CLASS:_: Str:D $literal, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfromstr_ip4(nqp::decont_s($literal), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: Blob:D $raw, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfrombuf_ip4(nqp::decont($raw), nqp::decont_i($port)))
    }

    method family(::?CLASS:_: --> PF_INET) { }

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

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}
    multi method new(::?CLASS:_: Str:D $literal, Port $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfromstr_ip6(nqp::decont_s($literal), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: Blob:D $raw, Port $port = 0, UInt:D :$scope-id = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), IO::Address, '$!VM-address',
          nqp::addrfrombuf_ip6(nqp::decont($raw), nqp::decont_i($port), nqp::decont_i($scope-id)))
    }

    method family(::?CLASS:_: --> PF_INET6) { }

    method scope-id(::?CLASS:D: --> Int:D) {
        nqp::addrscopeid(nqp::getattr(self, IO::Address, '$!VM-address'))
    }

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
