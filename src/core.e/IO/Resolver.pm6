my class IO::Resolver is repr('Resolver') { ... }

enum IO::Resolver::Type (
    T_A    => 1,
    T_AAAA => 28,
);

enum IO::Resolver::Class (
    C_IN => 1,
);

my class IO::Resolver {
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
        nqp::asyncdnsquery(self,
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
        nqp::asyncdnsquery(self,
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
            for await self.query: $host, C_IN, T_A -> IO::Address::IPv4:D $address {
                for @ipv4-solutions -> ($type, $protocol) {
                    emit $address.new: $port, :$type, :$protocol;
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
            for await self.query: $host, C_IN, T_AAAA -> IO::Address::IPv6:D $address {
                for @ipv6-solutions -> ($type, $protocol) {
                    emit $address.new: $port, :$type, :$protocol;
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
        # Implementation of RFC8305 (Happy Eyeballs v2):
        supply {
            # Begin by making an AAAA query followed by an A query,
            # in parallel, as closely together as we can:
            my (@ipv4-solutions, @ipv6-solutions) := take-a-hint $family, $type, $protocol;
            my Queue:D   $queue                   := nqp::create(Queue);
            my atomicint $init                     = 0;
            my Promise:D $query-aaaa              := self.query: $host, C_IN, T_AAAA;
            my Promise:D $query-a                 := self.query: $host, C_IN, T_A;
            my Promise:D $done-aaaa               := Promise.new;
            my Promise:D $done-a                  := Promise.new;
            whenever $query-aaaa -> @addresses {
                if cas $init, 0, 1 {
                    # IPv4 addresses were received first, despite the
                    # resolution delay. Proceed to sorting:
                    for @addresses {
                        my IO::Address::IPv6:D $peer   := .new: $port;
                        my IO::Address::IPv6:_ $source := try get-source-for $peer;
                        nqp::push($queue, AddressPair.new: :$source, :$peer, :!upgraded);
                    }
                } else {
                    # IPv6 addresses were received first. Proceed to
                    # connect with them:
                    for @addresses -> IO::Address::IPv6:D $peer {
                        for @ipv6-solutions -> ($type, $protocol) {
                            emit $peer.new: $port, :$type, :$protocol;
                        }
                    }
                }
                $done-aaaa.keep;
            }
            whenever $query-a -> @addresses {
                # If the first address we wind up receiving is an IPv4 one,
                # then await the recommended resolution delay of 50ms. If any
                # IPv6 addresses are received during that time, then proceed to
                # connect with those first. Either way, IPv4 addresses wind up
                # getting queued for sorting, if that ever happens.
                if ⚛$init {
                    for @addresses {
                        my IO::Address::IPv4:D $peer := .new: $port;
                        with try get-source-for $peer -> IO::Address::IPv4:D $source {
                            nqp::push($queue,
                              AddressPair.new: :source($source.upgrade), :peer($peer.upgrade), :upgraded);
                        } else {
                            nqp::push($queue,
                              AddressPair.new: :peer($peer.upgrade), :upgraded);
                        }
                    }
                    $done-a.keep;
                }
                else {
                    whenever Promise.in(0.050) {
                        cas $init, 0, 1;
                        for @addresses {
                            my IO::Address::IPv4:D $peer := .new: $port;
                            with try get-source-for $peer -> IO::Address::IPv4:D $source {
                                nqp::push($queue,
                                  AddressPair.new: :source($source.upgrade), :peer($peer.upgrade), :upgraded);
                            } else {
                                nqp::push($queue,
                                  AddressPair.new: :peer($peer.upgrade), :upgraded);
                            }
                        }
                        $done-a.keep;
                    }
                }
            }
            whenever Promise.allof: $done-aaaa, $done-a {
                # Signal the end of the queue:
                nqp::push($queue, AddressPair);
                # Sort the addresses, then emit the resulting addresses, completed with
                # the family/type/protocol hints given:
                for gather {
                    until (my AddressPair:_ $pair := nqp::shift($queue)) =:= AddressPair {
                        take $pair;
                    }
                }.sort(&address-sorter) -> AddressPair:D $pair {
                    if $pair.upgraded {
                        for @ipv4-solutions -> ($type, $protocol) {
                            emit $pair.peer.downgrade.new: $port, :$type, :$protocol
                        }
                    }
                    else {
                        for @ipv6-solutions -> ($type, $protocol) {
                            emit $pair.peer.new: $port, :$type, :$protocol
                        }
                    }
                }
                done;
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
            when SOCK_ANY    { $mask +|= 0b0011100 }
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

    # Helper routine for sorting addresses for the resolve method.
    sub address-sorter(AddressPair:D $a, AddressPair:D $b) {
        # Rule 1: Avoid unusable destinations.
        my Bool:D $a-source-defined := $a.source.DEFINITE;
        my Bool:D $b-source-defined := $b.source.DEFINITE;
        return Less if $a-source-defined && !$b-source-defined;
        return More if !$a-source-defined && $b-source-defined;

        if $a-source-defined && $b-source-defined {
            # Rule 2: Prefer matching scope.
            my Bool:D $a-scope-equal := $a.source.scope == $a.peer.scope;
            my Bool:D $b-scope-equal := $b.source.scope == $b.peer.scope;
            return Less if !$a-scope-equal && $b-scope-equal;
            return More if $a-scope-equal && !$b-scope-equal;

            # Rule 3: Avoid deprecated addresses.
            # TODO

            # Rule 4: Prefer home addresses.
            # TODO

            # Rule 5: Prefer matching label.
            # TODO

            # Rule 6: Prefer higher precedence.
            # TODO
        }

        # Rule 7: Prefer native transport.
        my Blob:D $a-peer-raw  := $a.peer.raw;
        my Blob:D $b-peer-raw  := $b.peer.raw;
        my Bool:D $a-is-native := not $a-peer-raw[0..9].all == 0 && $a-peer-raw[10..11].all == 0x00 | 0xFF;
        my Bool:D $b-is-native := not $b-peer-raw[0..9].all == 0 && $b-peer-raw[10..11].all == 0x00 | 0xFF;
        return Less if $a-is-native && !$b-is-native;
        return More if !$a-is-native && $b-is-native;

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
        my Exception:_ $error  := Exception;
        $addresses.tap(-> IO::Address:D $address {
            # Connection attempts are made one at a time, separated by at least
            # 10ms, but never taking any longer than 250ms (a naive connection
            # attempt delay). If we succeed within this time frame, we're done:
            await Promise.allof: Promise.anyof(start {
                $result.keep: try callback $address;
                $error := $!;
                done without $!;
            }, Promise.in(0.250)), Promise.in(0.010);
        }, done => {
            $result.break: $error with $error;
        });
        await $result
    };
}, '6.e';
