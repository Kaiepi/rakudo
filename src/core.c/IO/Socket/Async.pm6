my class IO::Socket::Async {
    my constant Port = IO::Address::IP::Port;

    my class SocketCancellation is repr('AsyncTask') { }

    has $!VMIO;
    has int $!udp;
    has $.enc;
    has $!encoder;
    has $!close-promise;
    has $!close-vow;

    has Str  $.peer-host;
    has Port $.peer-port is required;

    has Str  $.socket-host;
    has Port $.socket-port is required;

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
            -> Mu \bytes, Mu \err {
                if err {
                    $v.break(err);
                }
                else {
                    $v.keep(bytes);
                }
            },
            nqp::decont($b), SocketCancellation);
        $p
    }

    my class Datagram {
        has $.data;
        has str $.hostname;
        has int $.port;

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
    }

    my class SocketReaderTappable does Tappable {
        has $!VMIO;
        has $!scheduler;
        has $!buf;
        has $!close-promise;
        has $!udp;

        method new(Mu :$VMIO!, :$scheduler!, :$buf!, :$close-promise!, :$udp!) {
            self.CREATE!SET-SELF($VMIO, $scheduler, $buf, $close-promise, $udp)
        }

        method !SET-SELF(Mu $!VMIO, $!scheduler, $!buf, $!close-promise, $!udp) { self }

        method tap(&emit, &done, &quit, &tap) {
            my $buffer := nqp::list();
            my int $buffer-start-seq = 0;
            my int $done-target = -1;
            my int $finished = 0;

            sub emit-events() {
                until nqp::elems($buffer) == 0 || nqp::isnull(nqp::atpos($buffer, 0)) {
                    emit(nqp::shift($buffer));
                    $buffer-start-seq = $buffer-start-seq + 1;
                }
                if $buffer-start-seq == $done-target {
                    done();
                    $finished = 1;
                }
            }

            my $lock = Lock::Async.new;
            my $tap;
            $lock.protect: {
                my $cancellation := nqp::asyncreadbytes(nqp::decont($!VMIO),
                    $!scheduler.queue(:hint-affinity),
                    -> Mu \seq, Mu \data, Mu \err, Mu \hostname = Str, Mu \port = Int {
                        $lock.protect: {
                            unless $finished {
                                if err {
                                    quit(X::AdHoc.new(payload => err));
                                    $finished = 1;
                                }
                                elsif nqp::isconcrete(data) {
                                    my int $insert-pos = seq - $buffer-start-seq;
                                    if $!udp && nqp::isconcrete(hostname) && nqp::isconcrete(port) {
                                        nqp::bindpos($buffer, $insert-pos, Datagram.new(
                                            data => data,
                                            hostname => hostname,
                                            port => port
                                        ));
                                    } else {
                                        nqp::bindpos($buffer, $insert-pos, data);
                                    }
                                    emit-events();
                                }
                                else {
                                    $done-target = seq;
                                    emit-events();
                                }
                            }
                        }
                    },
                    nqp::decont($!buf), SocketCancellation);
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
                :$!VMIO, :$scheduler, :$buf, :$!close-promise, udp => $!udp && $datagram
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
                -> Mu \socket, Mu \err, Mu \peer-host, Mu \peer-port, Mu \socket-host, Mu \socket-port {
                    if err {
                        $v.break(err);
                    }
                    else {
                        my $client_socket := nqp::create(self);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!VMIO', socket);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!enc', $encoding.name);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!encoder',
                            $encoding.encoder());
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!peer-host', peer-host);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!peer-port', peer-port);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!socket-host', socket-host);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!socket-port', socket-port);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!family', $info.family);
                        setup-close($client_socket);
                        $v.keep($client_socket);
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
        has Promise $.socket-host;
        has Promise $.socket-port;

        submethod TWEAK(Promise :$!VMIO-tobe, Promise :$!family, Promise :$!socket-host, Promise :$!socket-port) { }

        method new(&on-close, *%rest) {
            self.bless: :&on-close, |%rest
        }

        method native-descriptor(--> Int) {
            nqp::filenofh(await $!VMIO-tobe)
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
            my Promise $VMIO-tobe   .= new;
            my Promise $family      .= new;
            my Promise $socket-host .= new;
            my Promise $socket-port .= new;
            my $VMIO-vow   = $VMIO-tobe.vow;
            my $family-vow = $family.vow;
            my $host-vow   = $socket-host.vow;
            my $port-vow   = $socket-port.vow;
            $lock.protect: {
                my $cancellation := &!bind($!host, $!resolver."$!method"($!host, $!port,
                    family   => $!family,
                    type     => SOCK_STREAM,
                    protocol => IPPROTO_TCP,
                    passive  => True,
                ), -> IO::Address::Info:D $info {
                    nqp::asynclisten(
                        $!scheduler.queue(:hint-affinity),
                        -> Mu \client-socket, Mu \err, Mu \peer-host, Mu \peer-port,
                           Mu \server-socket, Mu \socket-host, Mu \socket-port {
                            $lock.protect: {
                                if $finished {
                                    # do nothing
                                }
                                elsif err {
                                    my $exc = X::AdHoc.new(payload => err);
                                    quit($exc);
                                    $host-vow.break($exc) unless $host-vow.promise;
                                    $port-vow.break($exc) unless $port-vow.promise;
                                    $finished = 1;
                                }
                                elsif client-socket {
                                    my $client_socket := nqp::create(IO::Socket::Async);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!VMIO', client-socket);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!enc', $!encoding.name);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!encoder', $!encoding.encoder());
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!peer-host', peer-host);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!peer-port', peer-port);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!socket-host', socket-host);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!socket-port', socket-port);
                                    nqp::bindattr($client_socket, IO::Socket::Async,
                                        '$!family', $info.family);
                                    setup-close($client_socket);
                                    emit($client_socket);
                                }
                                elsif server-socket {
                                    $VMIO-vow.keep(server-socket);
                                    $family-vow.keep($info.family);
                                    $host-vow.keep(~socket-host);
                                    $port-vow.keep(+socket-port);
                                }
                            }
                        },
                        nqp::getattr($info.address, IO::Address, '$!VM-address'),
                        nqp::unbox_i($info.family.value),
                        $!backlog,
                        SocketCancellation);
                });
                $tap = ListenSocket.new: {
                    my $p = Promise.new;
                    my $v = $p.vow;
                    nqp::cancelnotify($cancellation, $!scheduler.queue, { $v.keep(True); });
                    $p
                }, :$VMIO-tobe, :$family, :$socket-host, :$socket-port;
                tap($tap);
                CATCH {
                    default {
                        tap($tap = ListenSocket.new({ Nil },
                            :$VMIO-tobe, :$family, :$socket-host, :$socket-port)) unless $tap;
                        quit($_);
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
            -> Mu \socket, Mu \err {
                if err {
                    $p.break(err);
                }
                else {
                    my $client_socket := nqp::create(self);
                    nqp::bindattr($client_socket, IO::Socket::Async, '$!VMIO', socket);
                    nqp::bindattr_i($client_socket, IO::Socket::Async, '$!udp', 1);
                    nqp::bindattr($client_socket, IO::Socket::Async, '$!enc', $encoding.name);
                    nqp::bindattr($client_socket, IO::Socket::Async, '$!encoder',
                        $encoding.encoder());
                    nqp::bindattr($client_socket, IO::Socket::Async, '$!family', nqp::decont($family));
                    setup-close($client_socket);
                    $p.keep($client_socket);
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
                -> Mu \socket, Mu \err {
                    if err {
                        $p.break(err);
                    }
                    else {
                        my $client_socket := nqp::create(self);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!VMIO', socket);
                        nqp::bindattr_i($client_socket, IO::Socket::Async, '$!udp', 1);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!enc', $encoding.name);
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!encoder',
                            $encoding.encoder());
                        nqp::bindattr($client_socket, IO::Socket::Async, '$!family', $info.family);
                        setup-close($client_socket);
                        $p.keep($client_socket);
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
            nqp::asyncwritebytesto(
                $!VMIO,
                $scheduler.queue,
                -> Mu \bytes, Mu \err {
                    if err {
                        $v.break(err);
                    }
                    else {
                        $v.keep(bytes);
                    }
                },
                nqp::getattr($info.address, IO::Address, '$!VM-address'),
                nqp::decont($b),
                SocketCancellation);
        });
        $p
    }
#?endif
}

# vim: expandtab shiftwidth=4
