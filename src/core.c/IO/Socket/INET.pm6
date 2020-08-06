my class IO::Socket::INET does IO::Socket {
    my module PIO {
        constant MIN_PORT = 0;
        constant MAX_PORT = 65_535; # RFC 793: TCP/UDP port limit

        subset Family   of Int:D where any SocketFamily.^enum_value_list;
        subset Type     of Int:D where any SocketType.^enum_value_list;
        subset Protocol of Int:D where any SocketProtocol.^enum_value_list;
    }

    has Str  $.host;
    has Int  $.port;
    has Str  $.localhost;
    has Int  $.localport;
    has Int  $.backlog;
    has Bool $.listening;

    # XXX: this could be a bit smarter about how it deals with unspecified
    # families...
    my sub split-host-port(:$host is copy, :$port is copy, :$family) {
        if ($host) {
            my ($split-host, $split-port) = $family == nqp::const::SOCKET_FAMILY_INET6
                ?? v6-split($host)
                !! v4-split($host);

            if $split-port {
                $host = $split-host.Str;
                $port //= $split-port.Int
            }
        }

        fail "Invalid port $port.gist(). Must be {PIO::MIN_PORT}..{PIO::MAX_PORT}"
            unless $port.defined and PIO::MIN_PORT <= $port <= PIO::MAX_PORT;

        return ($host, $port);
    }

    my sub v4-split($uri) {
        return $uri.split(':', 2);
    }

    my sub v6-split($uri) {
        my ($host, $port) = ($uri ~~ /^'[' (.+) ']' \: (\d+)$/)[0,1];
        return $host ?? ($host, $port) !! $uri;
    }

    # Create new socket that listens on $localhost:$localport
    multi method new(
        Bool           :$listen!          where .so,
        Str            :$localhost        is copy,
        Int            :$localport        is copy,
        PIO::Family    :$family           = nqp::const::SOCKET_FAMILY_UNSPEC,
        PIO::Type      :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol  :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
        IO::Resolver:D :$resolver         = $*RESOLVER,
        Str:D          :$method           = 'resolve',
                       *%rest,
        --> IO::Socket::INET:D
    ) {
        ($localhost, $localport) = (
            split-host-port :host($localhost), :port($localport), :$family
        orelse fail $_) unless $family == nqp::const::SOCKET_FAMILY_UNIX;

        self.bless(
            localhost => $localhost,
            localport => $localport,
            family    => SocketFamily($family),
            type      => SocketType($type),
            protocol  => SocketProtocol($protocol),
            listening => $listen,
            |%rest,
        )!initialize(:$resolver, :$method)
    }

    # Open new connection to socket on $host:$port
    multi method new(
        Str:D          :$host!            is copy,
        Int            :$port             is copy,
        PIO::Family    :$family           = nqp::const::SOCKET_FAMILY_UNSPEC,
        PIO::Type      :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol  :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
        IO::Resolver:D :$resolver         = $*RESOLVER,
        Str:D          :$method           = 'lookup',
                       *%rest,
        --> IO::Socket::INET:D
    ) {
        ($host, $port) = split-host-port(
            :$host,
            :$port,
            :$family,
        ) unless $family == nqp::const::SOCKET_FAMILY_UNIX;

        self.bless(
            host     => $host,
            port     => $port,
            family   => SocketFamily($family),
            type     => SocketType($type),
            protocol => SocketProtocol($protocol),
            |%rest,
        )!initialize(:$resolver, :$method)
    }

    # Fail if no valid parameters are passed
    multi method new() {
        fail "Nothing given for new socket to connect or bind to. "
            ~ "Invalid arguments to .new?";
    }

    method !initialize(IO::Resolver:D :$resolver!, Str:D :$method!) {
        my $PIO := nqp::socket($!listening ?? 10 !! 0);

        # Quoting perl5's SIO::INET:
        # If Listen is defined then a listen socket is created, else if the socket type,
        # which is derived from the protocol, is SOCK_STREAM then connect() is called.
        if $!listening || $!localhost || $!localport {
            if $!family == nqp::const::SOCKET_FAMILY_UNIX {
                # XXX: Doesn't belong here.
                my IO::Address::UNIX:D $address := IO::Address::UNIX.new: $!localhost.IO;
                nqp::bindsock($PIO,
                  nqp::getattr($address, IO::Address, '$!VM-address'),
                  nqp::unbox_i($!family.value),
                  nqp::unbox_i($!type.value),
                  nqp::unbox_i($!protocol.value),
                  nqp::unbox_i($!backlog || 128));
            } else {
                &*BIND($!localhost, $resolver."$method"($!localhost, $!localport || 0,
                    :$!family, :$!type, :$!protocol,
                    :passive,
                ), -> IO::Address::Info:D $info {
                    my Mu $result := nqp::bindsock($PIO,
                      nqp::getattr($info.address, IO::Address, '$!VM-address'),
                      nqp::unbox_i($info.family.value),
                      nqp::unbox_i($info.type.value),
                      nqp::unbox_i($info.protocol.value),
                      nqp::unbox_i($!backlog || 128));
                    nqp::bindattr(self, $?CLASS, '$!family', $info.family);
                    nqp::bindattr(self, $?CLASS, '$!type', $info.type);
                    nqp::bindattr(self, $?CLASS, '$!protocol', $info.protocol);
                    $result
                });
            }
        }

        if $!listening {
#?if !js
            $!localport = nqp::getport($PIO)
                   unless $!localport || ($!family == nqp::const::SOCKET_FAMILY_UNIX);
#?endif
        }
        elsif $!type == nqp::const::SOCKET_TYPE_STREAM {
            if $!family == nqp::const::SOCKET_FAMILY_UNIX {
                # XXX: Doesn't belong here.
                my IO::Address::UNIX:D $address := IO::Address::UNIX.new: $!host.IO;
                nqp::connect($PIO,
                  nqp::getattr($address, IO::Address, '$!VM-address'),
                  nqp::unbox_i($!family.value),
                  nqp::unbox_i($!type.value),
                  nqp::unbox_i($!protocol.value));
            } else {
                &*CONNECT($!host, $resolver."$method"($!host, $!port,
                    :$!family, :$!type, :$!protocol,
                    :passive, # For the sake of compatibility.
                ), -> IO::Address::Info:D $info {
                    my Mu $result := nqp::connect($PIO,
                      nqp::getattr($info.address, IO::Address, '$!VM-address'),
                      nqp::unbox_i($info.family.value),
                      nqp::unbox_i($info.type.value),
                      nqp::unbox_i($info.protocol.value));
                    nqp::bindattr(self, $?CLASS, '$!family', $info.family);
                    nqp::bindattr(self, $?CLASS, '$!type', $info.type);
                    nqp::bindattr(self, $?CLASS, '$!protocol', $info.protocol);
                    $result
                });
            }
        }

        nqp::bindattr(self, $?CLASS, '$!PIO', $PIO);
        self;
    }

    method connect(
        IO::Socket::INET:U:
        Str()           $host,
        Int()           $port,
        SocketFamily:D :$family   = PF_UNSPEC,
        IO::Resolver:D :$resolver = $*RESOLVER,
        Str:D          :$method   = 'lookup'
    ) {
        self.new:
            :$host, :$port, :family($family.value),
            :$resolver, :$method
    }

    method listen(
        IO::Socket::INET:U:
        Str()           $localhost,
        Int()           $localport,
        SocketFamily:D :$family     = PF_UNSPEC,
        IO::Resolver:D :$resolver   = $*RESOLVER,
        Str:D          :$method     = 'resolve',
    ) {
        self.new:
            :listen,
            :$localhost, :$localport, :family($family.value),
            :$resolver, :$method
    }

    method accept() {
        # A solution as proposed by moritz
        my $new_sock := $?CLASS.bless(:$!family, :$!type, :$!protocol, :$!nl-in);
        nqp::bindattr($new_sock, $?CLASS, '$!PIO',
            nqp::accept(nqp::getattr(self, $?CLASS, '$!PIO'))
        );
        return $new_sock;
    }

    method local-address(::?CLASS:D: --> IO::Address:D) {
        fail 'Socket not available' unless $!PIO;
        given nqp::getsockname($!PIO) -> [Int:D $family is raw, Mu $VM-address is raw] {
            my IO::Address:U \T = IO::Address[SocketFamily($family)];
            nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address)
        }
    }

    method remote-address(::?CLASS:D: --> IO::Address:D) {
        fail 'Socket not available' unless $!PIO;
        given nqp::getpeername($!PIO) -> [Int:D $family is raw, Mu $VM-address is raw] {
            my IO::Address:U \T = IO::Address[SocketFamily($family)];
            nqp::p6bindattrinvres(nqp::create(T), IO::Address, '$!VM-address', $VM-address)
        }
    }

    # IO::Socket::INET was originally written to treat socket families, types,
    # and protocols as integers. For compatibility reasons, these are still
    # exposed as such, but the following methods are to be removed in v6.e.

    method family(::?CLASS:D: --> Int:D) { $!family.value }

    method type(::?CLASS:D: --> Int:D) { $!type.value }

    method proto(::?CLASS:D: --> Int:D) {
        Rakudo::Deprecations.DEPRECATED:
            'IO::Socket::INET.protocol',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::INET.proto>;
        $!protocol.value
    }

    method protocol(::?CLASS:D: --> Int:D) { $!protocol.value }
}

# vim: expandtab shiftwidth=4
