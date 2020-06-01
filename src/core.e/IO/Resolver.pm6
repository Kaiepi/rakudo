my class IO::Resolver is repr('Resolver') { ... }

# TODO: nqp constants
enum IO::Resolver::Type (
    T_A    => 1,
    T_AAAA => 28,
);

# TODO: nqp constants
enum IO::Resolver::Class (
    C_IN => 1,
);

my class IO::Resolver {
    proto method query(::?CLASS:D: Str:D, ::Type:D, ::Class:D --> Promise:D) {*}
    multi method query(::?CLASS:D: Str:D $name, T_A $type, ::Class:D $class --> Promise:D) {
        start nqp::dnsquery(self, nqp::decont_s($name), nqp::unbox_i($type.value), nqp::unbox_i($class.value))
    }
    multi method query(::?CLASS:D: Str:D $name, T_AAAA $type, ::Class:D $class --> Promise:D) {
        start nqp::dnsquery(self, nqp::decont_s($name), nqp::unbox_i($type.value), nqp::unbox_i($class.value))
    }

    my subset AddressFamily   of ProtocolFamily:D where PF_UNSPEC | PF_INET | PF_INET6;
    my subset AddressType     of SocketType:D     where SOCK_ANY | SOCK_STREAM | SOCK_DGRAM | SOCK_RAW;
    my subset AddressProtocol of ProtocolType:D   where IPPROTO_ANY | IPPROTO_TCP | IPPROTO_UDP;

    my class Queue is repr('ConcBlockingQueue') { }

    proto method resolve(::?CLASS:D: Str:D, Int:D --> Iterable:D) {*}
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_INET :$family!;; AddressType:D :$type = SOCK_ANY, AddressProtocol:D :$protocol = IPPROTO_ANY
        --> Iterable:D
    ) {
        lazy gather {
            my (@ipv4-solutions, @) := take-a-hint $family, $type, $protocol;
            for await self.query: $host, T_A, C_IN -> Str:D $presentation {
                for @ipv4-solutions -> ($type, $protocol) {
                    take IO::Address::IPv4.new: $presentation, $port, :$type, :$protocol;
                }
            }
        }
    }
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_INET6 :$family!;; AddressType:D :$type = SOCK_ANY, AddressProtocol:D :$protocol = IPPROTO_ANY
        --> Iterable:D
    ) {
        lazy gather {
            my (@, @ipv6-solutions) := take-a-hint $family, $type, $protocol;
            for await self.query: $host, T_AAAA, C_IN -> Str:D $presentation {
                for @ipv6-solutions -> ($type, $protocol) {
                    take IO::Address::IPv6.new: $presentation, $port, :$type, :$protocol;
                }
            }
        }
    }
    multi method resolve(
        ::?CLASS:D:
        $host, $port,
        PF_UNSPEC :$family = PF_UNSPEC;; AddressType:D :$type = SOCK_ANY, AddressProtocol:D :$protocol = IPPROTO_ANY
        --> Iterable:D
    ) {
        # Implementation of RFC8305 (Happy Eyeballs v2):
        lazy gather {
            my (@ipv4-solutions, @ipv6-solutions) := take-a-hint $family, $type, $protocol;

            my Queue:D                   $queue     := nqp::create(Queue);
            my Bool:D                    $init      := False;
            my Lock:D                    $init_lock := Lock.new;
            my Lock::ConditionVariable:D $init_cond := $init_lock.condition;

            my &try-to-proceed := {
                unless $init {
                    $init := True;
                    $init_cond.signal;
                }
            };

            $init_lock.lock;
            $*SCHEDULER.cue({
                # Begin by making an AAAA query followed by an A query,
                # in parallel, as closely together as we can:
                await Promise.allof(start {
                    for await self.query: $host, T_AAAA, C_IN -> Str:D $presentation {
                        # If an IPv6 address was the first address
                        # received, then go ahead with connecting now:
                        FIRST try-to-proceed;
                        # Complete our IPv6 address(es) and push them to
                        # the queue:
                        for @ipv6-solutions -> ($type, $protocol) {
                            my IO::Address::IPv6 \address .= new: $presentation, $port, :$type, :$protocol;
                            nqp::push($queue, address);
                        }
                    }
                }, start {
                    for await self.query: $host, T_A, C_IN -> Str:D $presentation {
                        # If the first address we wind up receiving is an
                        # IPv4 one, then await the recommended resolution
                        # delay of 50ms before proceeding to connect with
                        # any addresses received during that point, so
                        # long as they're all IPv4 addresses:
                        FIRST $*SCHEDULER.cue: &try-to-proceed, in => 0.050 unless $init;
                        # Complete our IPv4 address(es) and push them
                        # to the queue:
                        for @ipv4-solutions -> ($type, $protocol) {
                            my IO::Address::IPv4 \address .= new: $presentation, $port, :$type, :$protocol;
                            nqp::push($queue, address);
                        }
                    }
                }).then({
                    # Mark the end of the queue:
                    nqp::push($queue, IO::Address);
                    # Ensure we can proceed to sort and connect:
                    try-to-proceed;
                });
            });
            $init_cond.wait;
            $init_lock.unlock;

            until (my IO::Address:_ $address := nqp::shift($queue)) =:= IO::Address {
                take $address;
            }
        }
    }

    # Helper routine for getting any extra address information not included in
    # the A/AAAA DNS records queried by IO::Resolver.resolve.
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
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver.new;
}, '6.e';

Rakudo::Internals.REGISTER-DYNAMIC: '&*CONNECT', {
    PROCESS::<&CONNECT> := sub CONNECT(Iterable:D $addresses is raw, &callback --> Nil) {
        my Exception:_ $error;
        for $addresses -> IO::Address:D $address {
            callback $address;
            CATCH { default {
                $error := $_;
                next;
            } }
            $error := Exception;
            last;
        }
        $error.rethrow with $error;
    };
}, '6.e';
