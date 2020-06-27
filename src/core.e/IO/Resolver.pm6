my class IO::Resolver { ... }

enum IO::Resolver::Type (
    T_A    => 1,
    T_AAAA => 28,
);

enum IO::Resolver::Class (
    C_IN => 1,
);

my class IO::Resolver {
    my class Context is repr('Resolver') { }

    my class Policy {
        has IO::Address::IPv6:D $.prefix     is required;
        has Int:D               $.length     is required where 0..128;
        has Int:D               $.label      is required;
        has Int:D               $.precedence is required;

        method matches(::?CLASS:D: IO::Address::IPv6:D $native-address --> Bool:D) {
            $native-address +& ((1 +< 129 - 1) +^ (1 +< (128 - $!length) - 1)) == $!prefix
        }
    }

    my class PolicyTable {
        has Policy:D @!policies;

        submethod BUILD(::?CLASS:D: :@policies! --> Nil) {
            @!policies = @policies.map(-> (Str:D $presentation, Int:D $length where 0..128, Int:D $label, Int:D $precedence) {
                my IO::Address::IPv6:D $prefix := IO::Address::IPv6.new: $presentation;
                Policy.new: :$prefix, :$length, :$label, :$precedence
            });
        }

        method new(::?CLASS:_: @policies --> ::?CLASS:D) {
            self.bless: :@policies
        }

        method lookup-label(::?CLASS:D: IO::Address::IPv6:D $address --> Int:D) {
            my Policy:D @matches = @!policies.grep: *.matches: $address;
            @matches ?? @matches».label.max !! 1
        }

        method lookup-precedence(::?CLASS:D: IO::Address::IPv6:D $address --> Int:D) {
            my Policy:D @matches = @!policies.grep: *.matches: $address;
            @matches ?? @matches».precedence.max !! 1
        }
    }

    has Context:D     $!context      is required;
    has PolicyTable:D $!policy-table is required;

    my constant @DEFAULT-POLICIES =
        ('::1', 128, 50, 0), ('::', 0, 40, 1), ('::FFFF:0:0', 96, 35, 4),
        ('2002::', 16, 30, 2), ('2001::', 32, 5, 5), ('FC00::', 7, 3, 13),
        ('::', 96, 1, 3), ('FEC0::', 10, 1, 11), ('3FFE::', 16, 1, 12);
    submethod BUILD(::?CLASS:D: :@policies = @DEFAULT-POLICIES --> Nil) {
        $!context      := nqp::create(Context);
        $!policy-table := PolicyTable.new: @policies;
    }

    my class Queue     is repr('ConcBlockingQueue') { }
    my class AsyncTask is repr('AsyncTask')         { }

    proto method query(::?CLASS:D: Str:D, ::Class:D, ::Type:D --> Promise:D) {*}
    multi method query(
        ::?CLASS:D:
        Str:D        $name,
        ::Class:D    $class,
        T_A          $type;;
        Scheduler:D :$scheduler = $*SCHEDULER
        --> Promise:D
    ) {
        my Promise:D $p := Promise.new;
        my           $v := $p.vow;
        nqp::asyncdnsquery($!context,
          nqp::decont_s($name),
          nqp::unbox_i($class.value),
          nqp::unbox_i($type.value),
          $scheduler.queue,
          -> Str:_ $error, @VM-addresses {
              with $error {
                  # TODO: Typed exception.
                  $v.break: X::AdHoc.new: payload => $error;
              }
              else {
                  $v.keep: @VM-addresses.map({
                      nqp::p6bindattrinvres(nqp::create(IO::Address::IPv4), IO::Address::IPv4, '$!VM-address', $_)
                  });
              }
          },
          AsyncTask);
        $p
    }
    multi method query(
        ::?CLASS:D:
        Str:D $name,
        ::Class:D    $class,
        T_AAAA       $type;;
        Scheduler:D :$scheduler = $*SCHEDULER
        --> Promise:D
    ) {
        my Promise:D $p := Promise.new;
        my           $v := $p.vow;
        nqp::asyncdnsquery($!context,
          nqp::decont_s($name),
          nqp::unbox_i($class.value),
          nqp::unbox_i($type.value),
          $scheduler.queue,
          -> Str:_ $error, @VM-addresses {
              with $error {
                  # TODO: Typed exception.
                  $v.break: X::AdHoc.new: payload => $error;
              }
              else {
                  $v.keep: @VM-addresses.map({
                      nqp::p6bindattrinvres(nqp::create(IO::Address::IPv6), IO::Address::IPv6, '$!VM-address', $_)
                  });
              }
          },
          AsyncTask);
        $p
    }

    my subset AddressFamily   of ProtocolFamily:D where PF_UNSPEC | PF_INET | PF_INET6;
    my subset AddressType     of SocketType:D     where SOCK_ANY | SOCK_STREAM | SOCK_DGRAM | SOCK_RAW;
    my subset AddressProtocol of ProtocolType:D   where IPPROTO_ANY | IPPROTO_TCP | IPPROTO_UDP;

    my class AddressPair {
        has IO::Address::IPv6:_ $.source;
        has IO::Address::IPv6:D $.peer     is required;
        has Bool:D              $.upgraded is required;
    }

    proto method resolve(::?CLASS:D: Str:D, Int:D --> Supply:D) {*}
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_INET           :$family!;;
        AddressType:D     :$type      = SOCK_ANY,
        AddressProtocol:D :$protocol  = IPPROTO_ANY
        --> Supply:D
    ) {
        supply {
            my (@ipv4-solutions, @) := take-a-hint $family, $type, $protocol;
            for (try IO::Address::IPv4.new: $host, $port)
             // await self.query: $host, C_IN, T_A -> IO::Address::IPv4:D $address {
                my IO::Address::IPv4:D $result := $address.new: $port;
                for @ipv4-solutions -> ($type, $protocol) {
                    emit IO::Address::Info.new: $result, :$type, :$protocol;
                }
            }
        }
    }
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_INET6          :$family!;;
        AddressType:D     :$type      = SOCK_ANY,
        AddressProtocol:D :$protocol  = IPPROTO_ANY
        --> Supply:D
    ) {
        supply {
            my (@, @ipv6-solutions) := take-a-hint $family, $type, $protocol;
            for (try IO::Address::IPv6.new: $host, $port)
             // await self.query: $host, C_IN, T_AAAA -> IO::Address::IPv6:D $address {
                my IO::Address::IPv6:D $result := $address.new: $port;
                for @ipv6-solutions -> ($type, $protocol) {
                    emit IO::Address::Info.new: $result, :$type, :$protocol;
                }
            }
        }
    }
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_UNSPEC         :$family   = PF_UNSPEC;;
        AddressType:D     :$type     = SOCK_ANY,
        AddressProtocol:D :$protocol = IPPROTO_ANY
        --> Supply:D
    ) {
        supply {
            my (@ipv4-solutions, @ipv6-solutions) := take-a-hint $family, $type, $protocol;

            # Check if the hostname given is really an IP address in its
            # presentation format, and emit the completed addresses immediately
            # if so:
            with try IO::Address::IPv6.new: $host, $port -> IO::Address::IPv6:D $result {
                for @ipv6-solutions -> ($type, $protocol) {
                    emit IO::Address::Info.new: $result, :$type, :$protocol;
                }
                done;
            }
            with try IO::Address::IPv4.new: $host, $port -> IO::Address::IPv4:D $result {
                for @ipv4-solutions -> ($type, $protocol) {
                    emit IO::Address::Info.new: $result, :$type, :$protocol;
                }
                done;
            }

            # Implementation of RFC8305 (Happy Eyeballs v2):

            # Queue up addresses to be sorted before connection attempts should
            # proceed:
            my Supplier:D $queue := Supplier.new;
            whenever $queue.Supply.sort({ self!compare-address-pairs: $^a, $^b }) -> AddressPair:D $pair {
                if $pair.upgraded {
                    for @ipv4-solutions -> ($type, $protocol) {
                        emit IO::Address::Info.new: $pair.peer.downgrade, :$type, :$protocol
                    }
                }
                else {
                    for @ipv6-solutions -> ($type, $protocol) {
                        emit IO::Address::Info.new: $pair.peer, :$type, :$protocol
                    }
                }
            }

            # Make an AAAA query followed by an A query, in parallel, as
            # closely together as we can:
            my Promise:D   $ipv6-answer := self.query: $host, C_IN, T_AAAA;
            my Promise:D   $ipv4-answer := self.query: $host, C_IN, T_A;
            my Semaphore:D $to-sort     := Semaphore.new: 1;
            whenever $ipv6-answer -> @addresses is raw {
                if $to-sort.try_acquire {
                    # IPv6 addresses were received first. Proceed to
                    # connect with them:
                    for @addresses -> IO::Address::IPv6:D $address {
                        my IO::Address::IPv6:D $result := $address.new: $port;
                        for @ipv6-solutions -> ($type, $protocol) {
                            emit IO::Address::Info.new: $result, :$type, :$protocol;
                        }
                    }
                } else {
                    # IPv4 addresses were received first, despite the
                    # resolution delay. Proceed to sorting:
                    for @addresses {
                        my IO::Address::IPv6:D $peer   := .new: $port;
                        my IO::Address::IPv6:_ $source := try get-source-for $peer;
                        $queue.emit: AddressPair.new: :$source, :$peer, :!upgraded;
                    }
                    $queue.done;
                }
            }
            whenever $ipv4-answer -> @addresses is raw {
                # If the first address we wind up receiving is an IPv4 one,
                # then await the recommended resolution delay of 50ms. If any
                # IPv6 addresses are received during that time, then proceed to
                # connect with those first. Either way, IPv4 addresses wind up
                # getting queued for sorting, if that ever happens.
                whenever Promise.anyof: $ipv6-answer, Promise.in: 0.050 {
                    my Bool:D $sorting := $to-sort.try_acquire;
                    for @addresses {
                        my IO::Address::IPv4:D $address := .new: $port;
                        my IO::Address::IPv6:D $peer    := $address.upgrade;
                        my IO::Address::IPv6:_ $source  := (try get-source-for $address).?upgrade // IO::Address::IPv6;
                        $queue.emit: AddressPair.new: :$source, :$peer, :upgraded;
                    }
                    $queue.done unless $sorting;
                }
            }
        }
    }

    # Helper routine for getting any extra address information not included in
    # the A/AAAA DNS records queried by the resolve method.
    #
    # getaddrinfo can only return addresses with hints matching a small set
    # of families, types, and protocols. This differs from platform to
    # platform, but the set here should be consistent among them:
    sub take-a-hint(AddressFamily:D $family, AddressType:D $type, AddressProtocol:D $protocol --> List:D) {
        state List:D %cache{Int:D};

        my Int:D $mask = 0;
        given $family { # Bits 6-7:
            when PF_INET   { $mask +|= 0b0100000 }
            when PF_INET6  { $mask +|= 0b1000000 }
            when PF_UNSPEC { $mask +|= 0b1100000 }
        }
        given $type { # Bits 3-5:
            when SOCK_DGRAM  { $mask +|= 0b0000100 }
            when SOCK_STREAM { $mask +|= 0b0001000 }
            when SOCK_RAW    { $mask +|= 0b0010000 }
            when SOCK_ANY    { $mask +|= 0b0001100 }
        }
        given $protocol { # Bits 1-2:
            when IPPROTO_UDP { $mask +|= 0b0000001 }
            when IPPROTO_TCP { $mask +|= 0b0000010 }
            when IPPROTO_ANY { $mask +|= 0b0000011 }
        }

        %cache{$mask} // %cache{$mask} = (( # IPv4 solutions:
            (do (SOCK_DGRAM, IPPROTO_UDP)  if $mask +& 0b0100101 == 0b0100101),
            (do (SOCK_STREAM, IPPROTO_TCP) if $mask +& 0b0101010 == 0b0101010),
            (do (SOCK_RAW, IPPROTO_ANY)    if $mask +& 0b0110011 == 0b0110011),
        ), ( # IPv6 solutions:
            (do (SOCK_DGRAM, IPPROTO_UDP)  if $mask +& 0b1000101 == 0b1000101),
            (do (SOCK_STREAM, IPPROTO_TCP) if $mask +& 0b1001010 == 0b1001010),
            (do (SOCK_RAW, IPPROTO_ANY)    if $mask +& 0b1010011 == 0b1010011),
        ))
    }

    # Helper routine for getting the source address to be used when making a
    # connection to a peer for the resolve method.
    sub get-source-for(::T IO::Address::IP:D $peer --> IO::Address::IP:_) {
        my Mu $socket := nqp::socket(0);
        LEAVE nqp::if(nqp::isconcrete($socket), nqp::closefh($socket));
        nqp::connect($socket,
          nqp::unbox_i($peer.family.Int), nqp::const::ADDRESS_TYPE_DGRAM, nqp::const::ADDRESS_PROTOCOL_UDP,
          nqp::getattr(nqp::decont($peer), T, '$!VM-address'));
        nqp::p6bindattrinvres(nqp::create(T), T, '$!VM-address', nqp::getsockname($socket))
    }

    method !compare-address-pairs(AddressPair:D $a, AddressPair:D $b --> Order:D) {
        # Rule 1: Avoid unusable destinations.
        my Bool:D  $a-source-defined := $a.source.DEFINITE;
        my Bool:D  $b-source-defined := $b.source.DEFINITE;
        my Order:D $source-defined   := $b-source-defined cmp $a-source-defined;
        return $source-defined if $source-defined;

        if $a-source-defined && $b-source-defined {
            # Rule 2: Prefer matching scope.
            my Order:D $scope-matches := reduce * cmp *, map {
                .source.scope == .peer.scope
            }, $b, $a;
            return $scope-matches if $scope-matches;

            # Rule 3: Avoid deprecated addresses.
            # TODO

            # Rule 4: Prefer home addresses.
            # TODO

            # Rule 5: Prefer matching label.
            my Order:D $label-matches := reduce * cmp *, map {
                [==] map { $!policy-table.lookup-label: $_ }, .source, .peer
            }, $b, $a;
            return $label-matches if $label-matches;
        }

        # Rule 6: Prefer higher precedence.
        my Order:D $precedence-cmp := reduce * cmp *, map {
            $!policy-table.lookup-precedence: .peer
        }, $b, $a;
        return $precedence-cmp if $precedence-cmp;

        # Rule 7: Prefer native transport.
        my Order:D $is-native := reduce * cmp *, map {
            .upgraded || .peer.is-ipv4-mapped || .peer.is-ipv4-compatible
        }, $b, $a;
        return $is-native if $is-native;

        # Rule 8: Prefer smaller scope.
        my Order:D $peer-scope-cmp := $a.peer.scope cmp $b.peer.scope;
        return $peer-scope-cmp if $peer-scope-cmp;

        # Rule 9: Use longest matching prefix.
        # TODO

        # Rule 10: Otherwise, leave the order unchanged.
        Same
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver.new;
}, '6.e';

Rakudo::Internals.REGISTER-DYNAMIC: '&*CONNECT', {
    PROCESS::<&CONNECT> := sub CONNECT(Supply:D $addresses is raw, &callback --> Mu) {
        my Promise:D   $result := Promise.new;
        my Exception:_ $error  := X::AdHoc.new: payload => "No addresses were received when resolving a hostname";
        my Tap:D       $tap    := $addresses.tap(-> IO::Address::Info:D $info is raw {
            my num $begin = nqp::time_n;
            await Promise.anyof: start {
                $result.keep: callback $info;
                $error := Exception;
                CATCH { default {
                    $error := $_;
                    await Promise.in: 0.100 - nqp::time_n + $begin;
                } }
            }, Promise.in: 2.000;
        }, done => {
            $result.break: $error with $error;
        });
        LEAVE $tap.close;
        await $result
    };
}, '6.e';
