my class IO::Socket::Async {
    my constant Port = IO::Address::IP::Port;

    my class SocketCancellation is repr('AsyncTask') { }

    has $!VMIO;
    has int $!udp;
    has $.enc;
    has $!encoder;
    has $!close-promise;
    has $!close-vow;

    has SocketFamily:D $.family is required;

    method new() {
        die "Cannot create an asynchronous socket directly; please use\n" ~
            "IO::Socket::Async.connect, IO::Socket::Async.listen,\n" ~
            "IO::Socket::Async.udp, or IO::Socket::Async.udp-bind";
    }

    method print(IO::Socket::Async:D: Str() $str, :$scheduler = $*SCHEDULER) {
        self.write($!encoder.encode-chars($str))
    }

    method write(IO::Socket::Async:D: Blob $b, :$scheduler = $*SCHEDULER) {
        my $p := Promise.new;
        my $v := $p.vow;
        nqp::asyncwritebytes(
            $!VMIO,
            $scheduler.queue,
            -> Str:_ $error is raw, Int:_ $bytes is raw {
                with $error {
                    $v.break: $error;
                }
                else {
                    $v.keep: $bytes;
                }
            },
            nqp::decont($b),
            SocketCancellation);
        $p
    }

    my class Datagram {
        has               $.data    is required;
        has IO::Address:D $.address is required;

        method decode(|c) {
            $!data ~~ Str
              ?? X::AdHoc.new( payload => "Cannot decode a datagram with Str data").throw
              !! self.clone(data => $!data.decode(|c))
        }

        method encode(|c) {
            $!data ~~ Blob
              ?? X::AdHoc.new( payload => "Cannot encode a datagram with Blob data" ).throw
              !! self.clone(data => $!data.encode(|c))
        }

        method hostname(::?CLASS:D: --> Str:D) {
            Rakudo::Deprecations.DEPRECATED:
                'IO::Socket::Async::Datagram.address.literal',
                '2020.FUTURE', # FIXME
                '6.e',
                :what<IO::Socket::Async::Datagram.hostname>;
            $!address.literal
        }

        method port(::?CLASS:D: --> Port) {
            Rakudo::Deprecations.DEPRECATED:
                'IO::Socket::Async::Datagram.address.port',
                '2020.FUTURE', # FIXME
                '6.e',
                :what<IO::Socket::Async::Datagram.port>;
            $!address.port
        }
    }

    my class SocketReaderTappable does Tappable {
        has $!VMIO;
        has $!scheduler;
        has $!buf;
        has $!close-promise;
        has $!udp;

        has SocketFamily:D $!family is required;

        method new(Mu :$VMIO!, :$scheduler!, :$buf!, :$close-promise!, :$udp!, :$family!) {
            self.CREATE!SET-SELF($VMIO, $scheduler, $buf, $close-promise, $udp, $family)
        }

        method !SET-SELF(Mu $!VMIO, $!scheduler, $!buf, $!close-promise, $!udp, $!family) { self }

        method tap(&emit, &done, &quit, &tap) {
            my $buffer := nqp::list();
            my int $buffer-start-seq = 0;
            my int $done-target = -1;
            my int $finished = 0;
            my $lock = Lock::Async.new;
            my $tap;
            $lock.protect: {
                my $cancellation := nqp::asyncreadbytes(nqp::decont($!VMIO),
                    $!scheduler.queue(:hint-affinity),
                    -> Str:_ $error is raw, Mu $data is raw, Int:_ $sequence is raw, Mu $VM-address is raw {
                        $lock.protect: {
                            if $finished {
                                # Nothing doing.
                            }
                            orwith $error {
                                quit X::AdHoc.new: payload => $error;
                                $finished = 1;
                            }
                            else {
                                my int $insert-pos = $sequence - $buffer-start-seq;
                                if nqp::isconcrete($data) {
                                    if $!udp && nqp::isconcrete($VM-address) {
                                        my IO::Address:U \T        = IO::Address[$!family];
                                        my IO::Address:D $address := nqp::p6bindattrinvres(
                                            nqp::create(T), IO::Address, '$!VM-address', $VM-address);
                                        nqp::bindpos($buffer, $insert-pos, Datagram.new: :$data, :$address);
                                    } else {
                                        nqp::bindpos($buffer, $insert-pos, $data);
                                    }
                                }
                                else {
                                    $done-target = $sequence;
                                }

                                while nqp::elems($buffer) && nqp::isconcrete(nqp::atpos($buffer, 0)) {
                                    emit nqp::shift($buffer);
                                    $buffer-start-seq = $buffer-start-seq + 1;
                                }

                                if $buffer-start-seq == $done-target {
                                    done;
                                    $finished = 1;
                                }
                            }
                        }
                    },
                    nqp::decont($!buf),
                    SocketCancellation);
                $tap := Tap.new({ nqp::cancel($cancellation) });
                tap($tap);
            }
            $!close-promise.then: {
                $lock.protect: {
                    unless $finished {
                        done();
                        $finished = 1;
                    }
                }
            }

            $tap
        }

        method live(--> False) { }
        method sane(--> True) { }
        method serial(--> True) { }
    }

    multi method Supply(IO::Socket::Async:D: :$bin, :$buf = nqp::create(buf8.^pun), :$datagram, :$enc, :$scheduler = $*SCHEDULER) {
        if $bin {
            Supply.new: SocketReaderTappable.new:
                :$!VMIO, :$scheduler, :$buf, :$!close-promise, udp => $!udp && $datagram,
                :$!family
        }
        else {
            my $bin-supply = self.Supply(:bin, :$datagram);
            if $!udp {
                supply {
                    whenever $bin-supply {
                        emit .decode($enc // $!enc);
                    }
                }
            }
            else {
                Rakudo::Internals.BYTE_SUPPLY_DECODER($bin-supply, $enc // $!enc)
            }
        }
    }

    method close(IO::Socket::Async:D: --> True) {
        nqp::closefh($!VMIO);
        try $!close-vow.keep(True);
    }

    method connect(
        IO::Socket::Async:U:
        Str()           $host,
        Int()           $port      where Port,
        SocketFamily:D :$family    = PF_UNSPEC,
        IO::Resolver:D :$resolver  = $*RESOLVER,
        Str:D          :$method    = 'lookup',
                       :$enc       = 'utf-8',
                       :$scheduler = $*SCHEDULER,
    ) {
        my $p = Promise.new;
        my $v = $p.vow;
        my $encoding = Encoding::Registry.find($enc);
        &*CONNECT($host, $resolver."$method"($host, $port,
            family   => $family,
            type     => SOCK_STREAM,
            protocol => IPPROTO_TCP,
            passive  => True, # For the sake of compatibility.
        ), -> IO::Address::Info:D $info {
            nqp::asyncconnect(
                $scheduler.queue,
                -> Str:_ $error is raw, Mu $VMIO is raw {
                    with $error {
                        $v.break: $error;
                    }
                    else {
                        my ::?CLASS:D $connection := nqp::create(self);
                        nqp::bindattr($connection, IO::Socket::Async, '$!VMIO', $VMIO);
                        nqp::bindattr($connection, IO::Socket::Async, '$!enc', $encoding.name);
                        nqp::bindattr($connection, IO::Socket::Async, '$!encoder', $encoding.encoder);
                        nqp::bindattr($connection, IO::Socket::Async, '$!family', $info.family);
                        $connection.&setup-close;
                        $v.keep: $connection;
                    }
                },
                nqp::getattr($info.address, IO::Address, '$!VM-address'),
                nqp::unbox_i($info.family.value),
                SocketCancellation)
        });
        $p
    }

    class ListenSocket is Tap {
        has Promise $!VMIO-tobe;
        has Promise $.family;

        submethod TWEAK(Promise :$!VMIO-tobe, Promise :$!family) { }

        method new(&on-close, *%rest) {
            self.bless: :&on-close, |%rest
        }

        method local-address(::?CLASS:D: --> Promise:D) {
            start given nqp::getsockname(await $!VMIO-tobe) -> [Int:D $family is raw, Mu $VM-address is raw] {
                my IO::Address:U \T = IO::Address[SocketFamily($family)];
                nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address)
            }
        }

        method native-descriptor(--> Int) {
            nqp::filenofh(await $!VMIO-tobe)
        }

        method socket-host(::?CLASS:D: --> Promise:D) {
            Rakudo::Internals.DEPRECATED:
                'the literal method of the address kept by IO::Socket::Async::ListenSocket.local-address',
                '2020.FUTURE', # FIXME
                '6.e',
                :what<IO::Socket::Async::ListenSocket.socket-host>;
            self.local-address.then: *.result.literal
        }

        method socket-port(::?CLASS:D: --> Promise:D) {
            Rakudo::Internals.DEPRECATED:
                'the port method of the address kept by IO::Socket::Async::ListenSocket.local-address',
                '2020.FUTURE', # FIXME
                '6.e',
                :what<IO::Socket::Async::ListenSocket.socket-port>;
            self.local-address.then: *.result.port
        }
    }

    my class SocketListenerTappable does Tappable {
        has                $!host;
        has                $!port;
        has SocketFamily:D $!family   is required;
        has                &!bind     is required;
        has IO::Resolver:D $!resolver is required;
        has Str:D          $!method   is required;

        has $!backlog;
        has $!encoding;
        has $!scheduler;

        method new(*%args) { self.CREATE!SET-SELF(|%args) }

        method !SET-SELF(
            :$!host, :$!port, :$!family,
            :&!bind, :$!resolver, :$!method,
            :$!backlog, :$!encoding, :$!scheduler,
        ) { self }

        method tap(&emit, &done, &quit, &tap) {
            my $lock := Lock::Async.new;
            my $tap;
            my int $finished = 0;
            my Promise $VMIO-tobe .= new;
            my Promise $family    .= new;
            my $VMIO-vow   = $VMIO-tobe.vow;
            my $family-vow = $family.vow;
            $lock.protect: {
                my $cancellation := &!bind($!host, $!resolver."$!method"($!host, $!port,
                    family   => $!family,
                    type     => SOCK_STREAM,
                    protocol => IPPROTO_TCP,
                    passive  => True,
                ), -> IO::Address::Info:D $info {
                    nqp::asynclisten(
                        $!scheduler.queue(:hint-affinity),
                        -> Str:_ $error is raw, Mu $VMIO-passive is raw, Mu $VMIO-active is raw {
                            $lock.protect: {
                                if $finished {
                                    # do nothing
                                }
                                orwith $error {
                                    quit X::AdHoc.new: payload => $error;
                                    $finished = 1;
                                }
                                elsif $VMIO-passive {
                                    $VMIO-vow.keep: $VMIO-passive;
                                    $family-vow.keep: $info.family;
                                }
                                else {
                                    my IO::Socket::Async:D $connection := nqp::create(IO::Socket::Async);
                                    nqp::bindattr($connection, IO::Socket::Async, '$!VMIO', $VMIO-active);
                                    nqp::bindattr($connection, IO::Socket::Async, '$!enc', $!encoding.name);
                                    nqp::bindattr($connection, IO::Socket::Async, '$!encoder', $!encoding.encoder);
                                    nqp::bindattr($connection, IO::Socket::Async, '$!family', $info.family);
                                    $connection.&setup-close;
                                    emit $connection;
                                }
                            }
                        },
                        nqp::getattr($info.address, IO::Address, '$!VM-address'),
                        nqp::unbox_i($info.family.value),
                        $!backlog,
                        SocketCancellation);
                });
                tap $tap := ListenSocket.new: {
                    my $p = Promise.new;
                    my $v = $p.vow;
                    nqp::cancelnotify($cancellation, $!scheduler.queue, { $v.keep(True); });
                    $p
                }, :$VMIO-tobe, :$family;
                CATCH {
                    default {
                        tap $tap := ListenSocket.new: { Nil }, :$VMIO-tobe, :$family unless $tap;
                        quit $_;
                    }
                }
            }
            $tap
        }

        method live(--> False) { }
        method sane(--> True) { }
        method serial(--> True) { }
    }

    method listen(
        IO::Socket::Async:U:
        Str()           $host,
        Int()           $port      where Port,
        Int()           $backlog   = 128,
        SocketFamily:D :$family    = PF_UNSPEC,
        IO::Resolver:D :$resolver  = $*RESOLVER,
        Str:D          :$method    = 'resolve',
                       :$enc       = 'utf-8',
                       :$scheduler = $*SCHEDULER,
    ) {
        my $encoding = Encoding::Registry.find($enc);
        my &bind     = &*BIND;
        Supply.new: SocketListenerTappable.new:
            :$host, :$port, :$family,
            :&bind, :$resolver, :$method,
            :$backlog, :$encoding, :$scheduler
    }

    method local-address(::?CLASS:D: --> IO::Address:D) {
        given nqp::getsockname($!VMIO) -> [Int:D $family is raw, Mu $VM-address is raw] {
            my IO::Address:U \T = IO::Address[SocketFamily($family)];
            nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address)
        }
    }

    method remote-address(::?CLASS:D: --> IO::Address:D) {
        given nqp::getpeername($!VMIO) -> [Int:D $family is raw, Mu $VM-address is raw] {
            my IO::Address:U \T = IO::Address[SocketFamily($family)];
            nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address)
        }
    }

    method native-descriptor(--> Int) {
        nqp::filenofh($!VMIO)
    }

    sub setup-close(\socket --> Nil) {
        my $p := Promise.new;
        nqp::bindattr(socket, IO::Socket::Async, '$!close-promise', $p);
        nqp::bindattr(socket, IO::Socket::Async, '$!close-vow', $p.vow);
    }

#?if moar
    method udp(
        IO::Socket::Async:U:
        SocketFamily:D :$family     = PF_UNSPEC,
                       :$broadcast,
                       :$enc        = 'utf-8',
                       :$scheduler  = $*SCHEDULER
    ) {
        my $p = Promise.new;
        my $encoding = Encoding::Registry.find($enc);
        nqp::asyncudp(
            $scheduler.queue,
            -> Str:_ $error is raw, Mu $VMIO is raw {
                with $error {
                    $p.break: $error;
                }
                else {
                    my ::?CLASS:D $socket := nqp::create(self);
                    nqp::bindattr($socket, IO::Socket::Async, '$!VMIO', $VMIO);
                    nqp::bindattr_i($socket, IO::Socket::Async, '$!udp', 1);
                    nqp::bindattr($socket, IO::Socket::Async, '$!enc', $encoding.name);
                    nqp::bindattr($socket, IO::Socket::Async, '$!encoder', $encoding.encoder);
                    nqp::bindattr($socket, IO::Socket::Async, '$!family', nqp::decont($family));
                    $socket.&setup-close;
                    $p.keep: $socket;
                }
            },
            nqp::null,
            nqp::unbox_i($family.value),
            $broadcast ?? 1 !! 0,
            SocketCancellation);
        await $p
    }

    method bind-udp(
        IO::Socket::Async:U:
        Str()           $host,
        Int()           $port       where Port,
        SocketFamily:D :$family     = PF_UNSPEC,
        IO::Resolver:D :$resolver   = $*RESOLVER,
        Str:D          :$method     = 'resolve',
                       :$broadcast,
                       :$enc        = 'utf-8',
                       :$scheduler  = $*SCHEDULER,
    ) {
        my $p = Promise.new;
        my $encoding = Encoding::Registry.find($enc);
        &*BIND($host, $resolver."$method"($host, $port,
            family   => $family,
            type     => SOCK_DGRAM,
            protocol => IPPROTO_UDP,
            passive  => True,
        ), -> IO::Address::Info:D $info {
            nqp::asyncudp(
                $scheduler.queue(:hint-affinity),
                -> Str:_ $error is raw, Mu $VMIO is raw {
                    with $error {
                        $p.break: $error;
                    }
                    else {
                        my ::?CLASS:D $binding := nqp::create(self);
                        nqp::bindattr($binding, IO::Socket::Async, '$!VMIO', $VMIO);
                        nqp::bindattr_i($binding, IO::Socket::Async, '$!udp', 1);
                        nqp::bindattr($binding, IO::Socket::Async, '$!enc', $encoding.name);
                        nqp::bindattr($binding, IO::Socket::Async, '$!encoder', $encoding.encoder);
                        nqp::bindattr($binding, IO::Socket::Async, '$!family', $info.family);
                        $binding.&setup-close;
                        $p.keep: $binding;
                    }
                },
                nqp::getattr($info.address, IO::Address, '$!VM-address'),
                nqp::unbox_i($info.family.value),
                $broadcast ?? 1 !! 0,
                SocketCancellation);
        });
        await $p
    }

    method print-to(
        IO::Socket::Async:D:
        Str()           $host,
        Int()           $port      where Port,
        Str()           $str,
        IO::Resolver:D :$resolver  = $*RESOLVER,
        Str:D          :$method    = 'lookup',
                       :$scheduler = $*SCHEDULER,
    ) {
        self.write-to: $host, $port, $!encoder.encode-chars($str),
            :$resolver, :$method, :$scheduler
    }

    method write-to(
        IO::Socket::Async:D:
        Str()           $host,
        Int()           $port      where Port,
        Blob            $b,
        IO::Resolver:D :$resolver  = $*RESOLVER,
        Str:D          :$method    = 'lookup',
                       :$scheduler = $*SCHEDULER,
    ) {
        my $p = Promise.new;
        my $v = $p.vow;
        &*CONNECT($host, $resolver."$method"($host, $port,
            family   => $!family,
            type     => SOCK_DGRAM,
            protocol => IPPROTO_UDP,
            passive  => True, # For the sake of compatibility.
        ), -> IO::Address::Info:D $info {
            nqp::asyncwritebytesto($!VMIO,
                $scheduler.queue,
                -> Str:_ $error is raw, Int:_ $bytes is raw {
                    with $error {
                        $v.break: $error;
                    }
                    else {
                        $v.keep: $bytes;
                    }
                },
                nqp::getattr($info.address, IO::Address, '$!VM-address'),
                nqp::decont($b),
                SocketCancellation);
        });
        $p
    }
#?endif

    method socket-host(::?CLASS:D: --> Str:D) {
        Rakudo::Internals.DEPRECATED:
            'IO::Socket::Async.local-address.literal',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::Async.socket-host>;
        self.local-address.literal
    }

    method socket-port(::?CLASS:D: --> Port) {
        Rakudo::Internals.DEPRECATED:
            'IO::Socket::Async.local-address.port',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::Async.socket-port>;
        self.local-address.port
    }

    method peer-host(::?CLASS:D: --> Str:D) {
        Rakudo::Internals.DEPRECATED:
            'IO::Socket::Async.remote-address.literal',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::Async.peer-host>;
        self.remote-address.literal
    }

    method peer-port(::?CLASS:D: --> Port) {
        Rakudo::Internals.DEPRECATED:
            'IO::Socket::Async.remote-address.port',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::Async.peer-port>;
        self.remote-address.port
    }
}

# vim: expandtab shiftwidth=4
