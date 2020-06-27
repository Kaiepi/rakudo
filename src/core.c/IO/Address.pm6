role  IO::Address       { ... }
class IO::Address::IPv6 { ... }

class IO::Address::Info {
    has IO::Address:D  $.address  is required;
    has SocketType:D   $.type     is required;
    has ProtocolType:D $.protocol is required;

    method new(::?CLASS:_: IO::Address:D $address, *%rest --> ::?CLASS:D) {
        self.bless: :$address, |%rest
    }

    method family(::?CLASS:D: --> ProtocolFamily:D) { $!address.family }
}

role IO::Address[ProtocolFamily:D $family] {
    has Mu $!VM-address is required;

    proto method new(::?ROLE:_: | --> ::?ROLE:D) {*}

    method family(::?CLASS:_: --> ProtocolFamily:D) { $family }
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

    multi method Stringy(::?CLASS:D: --> Stringy:D) { nqp::addrtopres($!VM-address) }
    multi method Str(::?CLASS:D: --> Str:D)         { nqp::addrtopres($!VM-address) }

    method IO(::?CLASS:D: --> IO::Path:D) { IO::Path.new: self.Str }

    multi method gist(::?CLASS:D: --> Str:D) { self.Str }

    multi method raku(::?CLASS:D: --> Str:D) {
        "IO::Address::UNIX.new($.Str.raku())";
    }
}

role IO::Address::IP is Cool {
    has Int:_ $!native;

    method raw(::?CLASS:D: --> Blob:D) { ... }
    method port(::?CLASS:D: --> Int:D) { ... }

    multi method Numeric(::?CLASS:D: --> Numeric:D) {
        $!native // ($!native := self.raw.contents.reduce: * +< 8 +| *)
    }
    multi method Int(::?CLASS:D: --> Int:D) {
        $!native // ($!native := self.raw.contents.reduce: * +< 8 +| *)
    }

    # XXX: Adding these stubs causes an error to be thrown while compiling the
    # setting.
    # multi method Stringy(::?CLASS:D: --> Stringy:D) { ... }
    # multi method Str(::?CLASS:D: --> Str:D)         { ... }
}

class IO::Address::IPv4 does IO::Address[PF_INET] does IO::Address::IP {
    multi method new(::?CLASS:_: Str:D $presentation, Int:D $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
          nqp::addrfromipv4pres(nqp::decont_s($presentation), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:_: blob8:D $raw where *.elems == 4, Int:D $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
          nqp::addrfromipv4native(nqp::decont($raw), nqp::decont_i($port)))
    }
    multi method new(::?CLASS:D: Int:D $port = 0 --> ::?CLASS:D) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address',
          nqp::addrfromipv4native(self.raw, nqp::decont_i($port)))
    }

    method raw(::?CLASS:D: --> blob8:D) { nqp::addrtonative($!VM-address, blob8.^pun) }
    method port(::?CLASS:D: --> Int:D)  { nqp::addrport($!VM-address) }

    # Convert to an IPv4-mapped IPv6 address, as IPv4-compatible IPv6 addresses
    # are deprecated.
    proto method upgrade(::?CLASS:D: --> IO::Address::IPv6:D) {*}
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($)! where ?*) {
        IO::Address::IPv6.new: "::$self", $.port
    }
    multi method upgrade(::?CLASS:D $self: Bool:D :compatible($) = False) {
        IO::Address::IPv6.new: "::FFFF:$self", $.port
    }

    multi method Stringy(::?CLASS:D: --> Stringy:D) { nqp::addrtopres($!VM-address) }
    multi method Str(::?CLASS:D: --> Str:D)         { nqp::addrtopres($!VM-address) }

    multi method gist(::?CLASS:D $self: --> Str:D) { "$self:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Int:D $port = $.port;
        my Str:D $raku = "IO::Address::IPv4.new($.Str.raku()";
        $raku ~= ", $port.raku()" unless $port == 0;
        $raku ~= ')';
        $raku
    }
}

# Refer to RFC4291 for information on what this class' methods do.
class IO::Address::IPv6 does IO::Address[PF_INET6] does IO::Address::IP {
    multi method new(
        ::?CLASS:_:
        Str:D   $presentation,
        Int:D   $port          = 0,
        UInt:D :$flowinfo      = 0,
        UInt:D :$scope-id      = 0
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address', nqp::addrfromipv6pres(
          nqp::decont_s($presentation), nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id)))
    }
    multi method new(
        ::?CLASS:_:
        blob8:D  $raw      where *.elems == 16,
        Int:D    $port     = 0,
        UInt:D  :$flowinfo = 0,
        UInt:D  :$scope-id = 0
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address', nqp::addrfromipv6native(
          nqp::decont($raw), nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id)))
    }
    multi method new(
        ::?CLASS:D:
        Int:D   $port     = 0,
        UInt:D :$flowinfo = 0,
        UInt:D :$scope-id = 0
        --> ::?CLASS:D
    ) {
        nqp::p6bindattrinvres(nqp::create(self), $?CLASS, '$!VM-address', nqp::addrfromipv6native(
          self.raw, nqp::decont_i($port), nqp::decont_i($flowinfo), nqp::decont_i($scope-id)))
    }

    method raw(::?CLASS:D: --> blob8:D)    { nqp::addrtonative($!VM-address, blob8.^pun) }
    method port(::?CLASS:D: --> Int:D)     { nqp::addrport($!VM-address) }
    method flowinfo(::?CLASS:D: --> Int:D) { nqp::addrflowinfo($!VM-address) }
    method scope-id(::?CLASS:D: --> Int:D) { nqp::addrscopeid($!VM-address) }

    method is-unicast(::?CLASS:D: --> Bool:D)   { self +> 124 != 0xFF }
    method is-multicast(::?CLASS:D: --> Bool:D) { self +> 124 == 0xFF }

    my subset Scope of Int:D where 0x0..0xF;
    method scope(::?CLASS:D: --> Scope) {
        nqp::stmts(
          (my int $upper-dword = self +> 64),
          # If the address is multicast, then the scope is whatever bits 13-16
          # are:
          nqp::if(
            ($upper-dword +& 0xFF00000000000000 == 0xFF00000000000000),
            ($upper-dword +& 0x000F000000000000),
            # If bits 1-10 are 1111111010 and bits 11-64 are all 0, then this
            # is a unicast link-local address:
            nqp::if(
              ($upper-dword +& 0xFFC0FFFFFFFFFFFF == 0xFE80000000000000),
              0x2,
              # If bits 1-10 are 1111111011, then this is a unicast site-local
              # address:
              nqp::if(
                ($upper-dword +& 0xFFC0000000000000 == 0xFEC0000000000000),
                0x4,
                # Otherwise, this is a unicast global address:
                0xE))))
    }

    method is-interface-local(::?CLASS:D: --> Bool:D)    { self.scope == 0x1 }
    method is-link-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x2 }
    method is-site-local(::?CLASS:D: --> Bool:D)         { self.scope == 0x4 }
    method is-admin-local(::?CLASS:D: --> Bool:D)        { self.scope == 0x5 }
    method is-organization-local(::?CLASS:D: --> Bool:D) { self.scope == 0x8 }
    method is-global(::?CLASS:D: --> Bool:D)             { self.scope == 0xE }

    method is-ipv4-compatible(::?CLASS:D: --> Bool:D) { self +> 32 == 0 }
    method is-ipv4-mapped(::?CLASS:D: --> Bool:D)     { self +> 32 +& 0xFFFF == 0xFFFF }

    method downgrade(::?CLASS:D $self: --> IO::Address::IPv4:D) {
        my blob8:D $raw-address := self.raw;
        # TODO: Typed exception.
        X::AdHoc.new(payload => "IPv6 address '$self' cannot be downgraded to IPv4").throw
            unless $raw-address[0..9].all == 0 && $raw-address[10..11].all == 0x00 | 0xFF;
        IO::Address::IPv4.new: $raw-address.subbuf(12, 4), $.port
    }

    multi method Stringy(::?CLASS:D: --> Stringy:D) { nqp::addrtopres($!VM-address) }
    multi method Str(::?CLASS:D: --> Str:D)         { nqp::addrtopres($!VM-address) }

    multi method gist(::?CLASS:D $self: --> Str:D) { "[$self]:$.port" }

    multi method raku(::?CLASS:D: --> Str:D) {
        my Int:D $port     = $.port;
        my Int:D $flowinfo = $.flowinfo;
        my Int:D $scope-id = $.scope-id;
        my Str:D $raku     = "IO::Address::IPv6.new($.Str.raku()";
        $raku ~= ", $port.raku()" unless $port == 0;
        $raku ~= ", flowinfo => $flowinfo.raku()" unless $flowinfo == 0;
        $raku ~= ", scope-id => $scope-id.raku()" unless $scope-id == 0;
        $raku ~= ")";
        $raku
    }
}
