role  IO::Address       { ... }
class IO::Address::IPv6 { ... }

class IO::Address::Info {
    has ProtocolFamily:D $.family   is required;
    has SocketType:D     $.type     is required;
    has ProtocolType:D   $.protocol is required;

    method new(::?CLASS:_: ProtocolFamily:D $family, SocketType:D $type, ProtocolType:D $protocol --> ::?CLASS:D) {
        nqp::create(self)!SET-SELF($family, $type, $protocol)
    }
    method !SET-SELF(::?CLASS:D: $family, $type, $protocol) {
        $!family   := $family;
        $!type     := $type;
        $!protocol := $protocol;
        self
    }
}

role IO::Address[ProtocolFamily:D $family] {
    has Mu                  $!VM-address is required;
    has IO::Address::Info:_ $.info;

    proto method new(::?ROLE:_: +, SocketType:_ :$type, ProtocolType:_ :$protocol --> ::?ROLE:D) {
        {*}!SET-SELF($type, $protocol)
    }
    method !SET-SELF(::?ROLE:D: $type, $protocol) {
        return self unless $type.DEFINITE && $protocol.DEFINITE;
        nqp::p6bindattrinvres(self, $?CLASS, '$!info',
           IO::Address::Info.new: $family, $type, $protocol)
    }

    multi method Str(::?CLASS:D: --> Str:D) { nqp::addrtopres($!VM-address) }
}

class IO::Address::UNIX does IO::Address[PF_UNIX] {
    multi method new(::?CLASS:_: IO::Path:D $path --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
          nqp::addrfrompath(nqp::unbox_s($path.Str)))
    }
    multi method new(::?CLASS:_: Str:D $path --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
          nqp::addrfrompath(nqp::decont_s($path)));
    }

    multi method gist(::?CLASS:D: --> Str:D) { self.Str }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Str:D $raku = "IO::Address::UNIX.new($.Str.raku()";
        $raku ~= ", type => $!info.type.raku(), protocol => $!info.protocol.raku()" with $!info;
        $raku ~= ')';
        $raku
    }
}

role IO::Address::IP {
    method raw(::?CLASS:D: --> Blob:D) { ... }
    method port(::?CLASS:D: --> Int:D) { ... }
}

class IO::Address::IPv4 does IO::Address[PF_INET] does IO::Address::IP {
    multi method new(::?CLASS:_: Str:D $ip, Int:D $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
            nqp::addrfromipv4(nqp::decont_s($ip), nqp::decont_i($port)))
    }

    method raw(::?CLASS:D: --> Blob:D) { nqp::addrtonative($!VM-address, blob8.^pun) }
    method port(::?CLASS:D: --> Int:D) { nqp::addrport($!VM-address) }

    # Convert to an IPv4-mapped IPv6 address, as IPv4-compatible IPv6 addresses
    # are deprecated.
    proto method upgrade(::?CLASS:D: --> IO::Address::IPv6:D) {*}
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($) = False) {
        IO::Address::IPv6.new: "::FFFF:$self", $.port, :$.type, :$.protocol
    }
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($)! where ?*) {
        IO::Address::IPv6.new: "::$self", $.port, :$.type, :$.protocol
    }

    multi method gist(::?CLASS:D $self: --> Str:D) { "$self:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Int:D $port = $.port;
        my Str:D $raku = "IO::Address::IPv4.new($.Str.raku()";
        $raku ~= ", $port.raku()" unless $port == 0;
        $raku ~= ", type => $!info.type.raku(), protocol => $!info.protocol.raku()" with $!info;
        $raku ~= ')';
        $raku
    }
}

# Refer to RFC4291 for information on what this class' methods do.
class IO::Address::IPv6 does IO::Address[PF_INET6] does IO::Address::IP {
    multi method new(::?CLASS:_: Str:D $ip, Int:D $port = 0, UInt:D :$flowinfo = 0, UInt:D :$scope-id = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address', nqp::addrfromipv6(
          nqp::decont_s($ip), nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id)))
    }

    method raw(::?CLASS:D: --> Blob:D)     { nqp::addrtonative($!VM-address, blob8.^pun) }
    method port(::?CLASS:D: --> Int:D)     { nqp::addrport($!VM-address) }
    method flowinfo(::?CLASS:D: --> Int:D) { nqp::addrflowinfo($!VM-address) }
    method scope-id(::?CLASS:D: --> Int:D) { nqp::addrscopeid($!VM-address) }

    method is-unicast(::?CLASS:D: --> Bool:D)   { self.raw.[0] != 0xFF }
    method is-multicast(::?CLASS:D: --> Bool:D) { self.raw.[0] == 0xFF }

    subset Scope of Int:D where 0x0..0xF;
    method scope(::?CLASS:D: --> Scope) {
        my Blob:D $address := self.raw;
        # If the address is multicast, then the scope is whatever bits 13-16 are:
        return $address[1] +& 0x0F if $address[0] == 0xFF;
        # If bits 1-10 are 1111111010 and bits 11-64 are all 0, then this is a
        # unicast link-local address:
        return 0x2 if $address[0] == 0xFE
                   && $address[1] +& 0xC0 == 0x80
                   && $address[2..7].reduce({ $^a +< 8 +| $^b }) == 0;
        # If bits 1-10 are 1111111011, then this is a unicast site-local
        # address:
        return 0x4 if $address[0] == 0xFE
                   && $address[1] +& 0xC0 == 0xC0;
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
        my Int:D $native-address := self.raw.reduce({ $^a +< 8 +| $^b });
        $native-address +& 0xFFFFFFFF == $native-address
    }

    method is-ipv4-mapped(::?CLASS:D: --> Bool:D) {
        my Int:D $native-address := self.raw.reduce({ $^a +< 8 +| $^b });
        my Int:D $tail           := $native-address +& 0xFFFFFFFFFFFF;
        $tail == $native-address && $tail +> 32 == 0xFFFF
    }

    method downgrade(::?CLASS:D $self: --> IO::Address::IPv4:D) {
        my Int:D $native-address := self.raw.reduce({ $^a +< 8 +| $^b });
        my Int:D $tail           := $native-address +& 0xFFFFFFFFFFFF;
        my Int:D $maybe-ipv4     := $tail +& 0xFFFFFFFF;
        # TODO: Typed exception.
        X::AdHoc.new(payload => "IPv6 address '$self' cannot be downgraded to IPv4").throw
            unless $maybe-ipv4 == $native-address || ($tail == $native-address && $tail +> 32 == 0xFFFF);

        # TODO: Similar ops to nqp::addrfromipv4/nqp::addrfromipv6 for blobs.
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
        $raku ~= ", type => $!info.type.raku(), protocol => $!info.protocol.raku()" with $!info;
        $raku ~= ')';
        $raku
    }
}
