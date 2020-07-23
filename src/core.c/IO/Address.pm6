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
}
