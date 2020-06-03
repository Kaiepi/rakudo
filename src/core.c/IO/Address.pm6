role IO::Address[ProtocolFamily:D $family] {
    has SocketType:D   $.type       is required;
    has ProtocolType:D $.protocol   is required;
    has Mu             $!VM-address is required;

    proto method new(::?CLASS:_: | --> ::?CLASS:D) {*}

    method family(::?CLASS:D: --> ProtocolFamily:D) { $family }

    multi method Str(::?CLASS:D: --> Str:D) { nqp::addrtopres($!VM-address) }
}

class IO::Address::UNIX does IO::Address[PF_UNIX] {
    multi method new(
        ::SELF ::?CLASS:_:
        IO::Path:D      $path,
        SocketType:D   :$type     = SOCK_ANY,
        ProtocolType:D :$protocol = IPPROTO_ANY
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self :=
            nqp::p6bindattrinvres(nqp::create(self), SELF, '$!VM-address',
                nqp::addrfrompath(nqp::unbox_s(~$path)));
        nqp::bindattr($self, SELF, '$!type', nqp::decont($type));
        nqp::bindattr($self, SELF, '$!protocol', nqp::decont($protocol));
        $self
    }
    multi method new(
        ::SELF ::?CLASS:_:
        Str:D           $path,
        SocketType:D   :$type     = SOCK_ANY,
        ProtocolType:D :$protocol = IPPROTO_ANY
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self :=
            nqp::p6bindattrinvres(nqp::create(self), SELF, '$!VM-address',
                nqp::addrfrompath(nqp::decont_s($path)));
        nqp::bindattr($self, SELF, '$!type', nqp::decont($type));
        nqp::bindattr($self, SELF, '$!protocol', nqp::decont($protocol));
        $self
    }

    multi method gist(::?CLASS:D: --> Str:D) { self.Str }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Str:D $raku = "IO::Address::UNIX.new($.Str.raku()";
        $raku ~= ", type => $!type.raku()" unless $!type ~~ SOCK_STREAM;
        $raku ~= ", protocol => $!protocol.raku()" unless $!protocol ~~ IPPROTO_TCP;
        $raku ~= ')';
        $raku
    }
}

role IO::Address::IP {
    method port(::?CLASS:D: --> Int:D) { ... }
}

class IO::Address::IPv6 { ... }

class IO::Address::IPv4 does IO::Address[PF_INET] does IO::Address::IP {
    multi method new(
        ::SELF ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port     = 0,
        SocketType:D   :$type     = SOCK_ANY,
        ProtocolType:D :$protocol = IPPROTO_ANY
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self :=
            nqp::p6bindattrinvres(nqp::create(self), SELF, '$!VM-address',
                nqp::addrfromipv4(nqp::decont_s($ip), nqp::decont_i($port)));
        nqp::bindattr($self, SELF, '$!type', nqp::decont($type));
        nqp::bindattr($self, SELF, '$!protocol', nqp::decont($protocol));
        $self
    }

    method port(::?CLASS:D: --> Int:D) { nqp::addrport($!VM-address) }

    method Int(::?CLASS:D: --> Int:D) { nqp::addrtonative($!VM-address) }

    multi method Numeric(::?CLASS:D: --> Numeric:D) { self.Int }

    # Convert to an IPv4-mapped IPv6 address, as IPv4-compatible IPv6 addresses
    # are deprecated.
    proto method upgrade(::?CLASS:D: --> IO::Address::IPv6:D) {*}
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($) = False) {
        IO::Address::IPv6.new: "::FFFF:$self", $.port, :$.type, :$.protocol
    }
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($)! where ?*) {
        IO::Address::IPv4.new: "::$self", $.port, :$.type, :$.protocol
    }

    multi method gist(::?CLASS:D $self: --> Str:D) { "$self:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Int:D $port = $.port;
        my Str:D $raku = "IO::Address::IPv4.new($.Str.raku()";
        $raku ~= ", $port.raku()" unless $port == 0;
        $raku ~= ", type => $!type.raku()" unless $!type ~~ SOCK_STREAM;
        $raku ~= ", protocol => $!protocol.raku()" unless $!protocol ~~ IPPROTO_TCP;
        $raku ~= ')';
        $raku
    }
}

# Refer to RFC4291 for information on what this class' methods do.
class IO::Address::IPv6 does IO::Address[PF_INET6] does IO::Address::IP {
    multi method new(
        ::SELF ::?CLASS:_:
        Str:D           $ip,
        Int:D           $port     = 0,
        UInt:D         :$flowinfo = 0,
        UInt:D         :$scope-id = 0,
        SocketType:D   :$type     = SOCK_ANY,
        ProtocolType:D :$protocol = IPPROTO_ANY
        --> ::?CLASS:D
    ) {
        my ::?CLASS:D $self :=
            nqp::p6bindattrinvres(nqp::create(self), SELF, '$!VM-address',
                nqp::addrfromipv6(nqp::decont_s($ip), nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id)));
        nqp::bindattr($self, SELF, '$!type', nqp::decont($type));
        nqp::bindattr($self, SELF, '$!protocol', nqp::decont($protocol));
        $self
    }

    method port(::?CLASS:D: --> Int:D)     { nqp::addrport($!VM-address) }
    method flowinfo(::?CLASS:D: --> Int:D) { nqp::addrflowinfo($!VM-address) }
    method scope-id(::?CLASS:D: --> Int:D) { nqp::addrscopeid($!VM-address) }

    method Int(::?CLASS:D: --> Int:D) { nqp::addrtonative($!VM-address) }

    multi method Numeric(::?CLASS:D: --> Numeric:D) { self.Int }

    method is-unicast(::?CLASS:D: --> Bool:D)   { self.Int +> 120 != 0xFF }
    method is-multicast(::?CLASS:D: --> Bool:D) { self.Int +> 120 == 0xFF }

    subset Scope of Int:D where 0x0..0xF;
    method scope(::?CLASS:D: --> Scope) {
        my Int:D $native-address := self.Int;
        my Int:D $leading-word   := $native-address +> 112;
        # If the address is multicast, then the scope is whatever bits 13-16 are:
        return $leading-word +& 0x000F if $leading-word +> 8 == 0xFF;
        # If bits 1-10 are 1111111010 and bits 11-64 are all 0, then this is a
        # unicast link-local address:
        return 0x2 if $leading-word == 0xFE80 && $native-address +> 64 +& 0x0000FFFFFFFFFFFF == 0;
        # If bits 1-10 are 1111111011, then this is a unicast site-local
        # address:
        return 0x4 if $leading-word == 0xFEC0;
        # Otherwise, this is a unicast global address:
        0xE
    }

    method is-interface-local(::?CLASS:D: --> Bool:D)    { self.scope == 0x1 }
    method is-link-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x2 }
    method is-site-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x4 }
    method is-admin-local(::?CLASS:D: --> Bool:D)        { self.scope == 0x5 }
    method is-organization-local(::?CLASS:D: --> Bool:D) { self.scope == 0x8 }
    method is-global(::?CLASS:D: --> Bool:D)             { self.scope == 0xE }

    method is-ipv4-compatible(::?CLASS:D: --> Bool:D) {
        my Int:D $native-address := self.Int;
        $native-address +& 0xFFFFFFFF == $native-address
    }

    method is-ipv4-mapped(::?CLASS:D: --> Bool:D) {
        my Int:D $native-address := self.Int;
        my Int:D $tail           := $native-address +& 0xFFFFFFFFFFFF;
        $tail == $native-address && $tail +> 32 == 0xFFFF
    }

    method downgrade(::?CLASS:D $self: --> IO::Address::IPv4:D) {
        my Int:D $native-address := self.Int;
        my Int:D $tail           := $native-address +& 0xFFFFFFFFFFFF;
        my Int:D $maybe-ipv4     := $tail +& 0xFFFFFFFF;
        # TODO: Typed exception.
        X::AdHoc.new(payload => "IPv6 address '$self' cannot be downgraded to IPv4").throw
            unless $maybe-ipv4 == $native-address || ($tail == $native-address && $tail +> 32 == 0xFFFF);

        # TODO: nqp::addrfromipv4/nqp::addrfromipv6 should have _I and _s
        # counterparts so this and .new can work better.
        my Str:D $presentation := join '.', $maybe-ipv4 +& 0xFF000000 +> 24, $maybe-ipv4 +& 0x00FF0000 +> 16,
                                            $maybe-ipv4 +& 0x0000FF00 +> 8, $maybe-ipv4 +& 0x000000FF;
        IO::Address::IPv4.new: $presentation, $.port, :$.type, :$.protocol
    }

    multi method gist(::?CLASS:D $self: --> Str:D) { "[$self]:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Int:D $port     = $.port;
        my Int:D $flowinfo = $.flowinfo;
        my Int:D $scope-id = $.scope-id;
        my Str:D $raku     = "IO::Address::IPv6.new($.Str.raku()";
        $raku ~= ", $port.raku()" unless $port == 0;
        $raku ~= ", flowinfo => $flowinfo.raku()" unless $flowinfo == 0;
        $raku ~= ", scope-id => $scope-id.raku()" unless $scope-id == 0;
        $raku ~= ", type => $!type.raku()" unless $!type ~~ SOCK_STREAM;
        $raku ~= ", protocol => $!protocol.raku()" unless $!protocol ~~ IPPROTO_TCP;
        $raku ~= ')';
        $raku
    }
}
