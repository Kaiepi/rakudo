my class IO::Socket::INET does IO::Socket {
    my module PIO {
        constant MIN_PORT = 0;
        constant MAX_PORT = 65_535; # RFC 793: TCP/UDP port limit

        subset Family   of Int:D where any SocketFamily.^enum_value_list;
        subset Type     of Int:D where any SocketType.^enum_value_list;
        subset Protocol of Int:D where any SocketProtocol.^enum_value_list;
    }

    has Str  $!host       is built;
    has Int  $!port       is built;
    has Str  $!localhost  is built;
    has Int  $!localport  is built;
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

    # Create a new socket that listens on an explicit IP address
    multi method new(
        Bool:D            :$listen!          where ?*,
        IO::Address::IP:D :$address!,
        PIO::Family       :$family           = $address.family.value,
        PIO::Type         :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol     :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
                          *%rest
    ) {
        self.bless(
            family    => SocketFamily($family),
            type      => SocketType($type),
            protocol  => SocketProtocol($protocol),
            listening => $listen,
            |%rest,
        )!LISTEN-DIRECT($address)
    }
    method !LISTEN-DIRECT(::?CLASS:D: IO::Address::IP:D $address --> ::?CLASS:D) {
        nqp::bindattr(self, $?CLASS, '$!PIO', nqp::socket(1));
        nqp::bindsock($!PIO,
          nqp::getattr(nqp::decont($address), IO::Address, '$!VM-address'),
          nqp::unbox_i($!family.value),
          nqp::unbox_i($!type.value),
          nqp::unbox_i($!protocol.value),
          nqp::unbox_i($!backlog || 128));
        self
    }

    # Create new socket that listens on $localhost:$localport
    multi method new(
        Bool           :$listen!          where .so,
        Str            :$localhost,
        Int            :$localport,
        PIO::Family    :$family           = nqp::const::SOCKET_FAMILY_UNSPEC,
        PIO::Type      :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol  :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
        IO::Resolver:D :$resolver         = $*RESOLVER,
        Str:D          :$method           = 'resolve',
                       *%rest,
        --> IO::Socket::INET:D
    ) {
        self.bless(
            localhost => $localhost,
            localport => $localport,
            family    => SocketFamily($family),
            type      => SocketType($type),
            protocol  => SocketProtocol($protocol),
            listening => $listen,
            |%rest,
        )!LISTEN($localhost, $localport, :$resolver, :$method)
    }
    method !LISTEN(
        ::?CLASS:D:
        Str:_           $host       is copy,
        Int:_           $port       is copy,
        IO::Resolver:D :$resolver!,
        Str:D          :$method!
        --> ::?CLASS:D
    ) {
        nqp::bindattr(self, $?CLASS, '$!PIO', nqp::socket(1));
        if $!family == PF_UNIX {
            # XXX: Doesn't belong here.
            my IO::Address::UNIX:D $address := IO::Address::UNIX.new: $host.IO;
            nqp::bindsock($!PIO,
              nqp::getattr($address, IO::Address, '$!VM-address'),
              nqp::unbox_i($!family.value),
              nqp::unbox_i($!type.value),
              nqp::unbox_i($!protocol.value),
              nqp::unbox_i($!backlog || 128));
            self
        }
        orwith split-host-port :$host, :$port, :$!family -> [Str:_ $host is copy, Int:_ $port is copy] {
            $host //= '0.0.0.0';
            $port //= 0;
            &*BIND($host, $resolver."$method"($host, $port,
                :$!family, :$!type, :$!protocol,
                :passive,
            ), -> IO::Address::Info:D $info {
                my Mu $result := nqp::bindsock($!PIO,
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
            self
        }
        else { .&fail }
    }

    # Open new connection to socket on an explicit IP address
    multi method new(
        IO::Address::IP:D :$address!,
        PIO::Family       :$family           = $address.family.value,
        PIO::Type         :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol     :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
                          *%rest
    ) {
        self.bless(
            family    => SocketFamily($family),
            type      => SocketType($type),
            protocol  => SocketProtocol($protocol),
            |%rest,
        )!CONNECT-DIRECT($address)
    }
    method !CONNECT-DIRECT(::?CLASS:D: IO::Address::IP:D $address --> ::?CLASS:D) {
        nqp::bindattr(self, $?CLASS, '$!PIO', nqp::socket(0));
        nqp::connect($!PIO,
          nqp::getattr(nqp::decont($address), IO::Address, '$!VM-address'),
          nqp::unbox_i($!family.value),
          nqp::unbox_i($!type.value),
          nqp::unbox_i($!protocol.value));
        self
    }

    # Open new connection to socket on $host:$port
    multi method new(
        Str:D          :$host!,
        Int            :$port,
        PIO::Family    :$family           = nqp::const::SOCKET_FAMILY_UNSPEC,
        PIO::Type      :$type             = nqp::const::SOCKET_TYPE_STREAM,
        PIO::Protocol  :proto(:$protocol) = nqp::const::SOCKET_PROTOCOL_ANY,
        IO::Resolver:D :$resolver         = $*RESOLVER,
        Str:D          :$method           = 'lookup',
                       *%rest,
        --> IO::Socket::INET:D
    ) {
        self.bless(
            host     => $host,
            port     => $port,
            family   => SocketFamily($family),
            type     => SocketType($type),
            protocol => SocketProtocol($protocol),
            |%rest,
        )!CONNECT($host, $port, :$resolver, :$method)
    }
    method !CONNECT(::?CLASS:D: Str:D $host, Int:_ $port, IO::Resolver:D :$resolver!, Str:D :$method! --> ::?CLASS:D) {
        nqp::bindattr(self, $?CLASS, '$!PIO', nqp::socket(0));
        if $!family == PF_UNIX {
            # XXX: Doesn't belong here.
            my IO::Address::UNIX:D $address := IO::Address::UNIX.new: $host.IO;
            nqp::connect($!PIO,
              nqp::getattr($address, IO::Address, '$!VM-address'),
              nqp::unbox_i($!family.value),
              nqp::unbox_i($!type.value),
              nqp::unbox_i($!protocol.value));
            self
        }
        orwith split-host-port :$host, :$port, :$!family -> [Str:_ $host is copy, Int:_ $port is copy] {
            &*CONNECT($host, $resolver."$method"($host, $port,
                :$!family, :$!type, :$!protocol,
                :passive, # For the sake of compatibility.
            ), -> IO::Address::Info:D $info {
                my Mu $result := nqp::connect($!PIO,
                  nqp::getattr($info.address, IO::Address, '$!VM-address'),
                  nqp::unbox_i($info.family.value),
                  nqp::unbox_i($info.type.value),
                  nqp::unbox_i($info.protocol.value));
                nqp::bindattr(self, $?CLASS, '$!family', $info.family);
                nqp::bindattr(self, $?CLASS, '$!type', $info.type);
                nqp::bindattr(self, $?CLASS, '$!protocol', $info.protocol);
                $result
            });
            self
        }
        else { .&fail }
    }

    # Fail if no valid parameters are passed
    multi method new() {
        fail "Nothing given for new socket to connect or bind to. "
            ~ "Invalid arguments to .new?";
    }

    proto method connect(|) {*}
    multi method connect(
        ::?CLASS:U:
        IO::Address::IP:D  $address,
        SocketFamily:D    :$family   = $address.family,
        --> ::?CLASS:D
    ) {
        self.new: :$address, :family($family.value)
    }
    multi method connect(
        ::?CLASS:U:
        Str()           $host,
        Int()           $port,
        SocketFamily:D :$family   = PF_UNSPEC,
        IO::Resolver:D :$resolver = $*RESOLVER,
        Str:D          :$method   = 'lookup'
        --> ::?CLASS:D
    ) {
        self.new:
            :$host, :$port, :family($family.value),
            :$resolver, :$method
    }

    proto method listen(|) {*}
    multi method listen(
        ::?CLASS:U:
        IO::Address::IP:D  $address,
        SocketFamily:D    :$family   = $address.family,
        --> ::?CLASS:D
    ) {
        self.new: :listen, :$address, :family($family.value)
    }
    multi method listen(
        ::?CLASS:U:
        Str()           $localhost,
        Int()           $localport,
        SocketFamily:D :$family     = PF_UNSPEC,
        IO::Resolver:D :$resolver   = $*RESOLVER,
        Str:D          :$method     = 'resolve',
        --> ::?CLASS:D
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

    method localhost(::?CLASS:D: --> Str:_) {
        Rakudo::Deprecations.DEPRECATED:
            'IO::Socket::INET.local-address.literal',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::INET.localhost>;
        $!localhost
    }

    method localport(::?CLASS:D: --> Int:_) {
        Rakudo::Deprecations.DEPRECATED:
            'IO::Socket::INET.local-address.port',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::INET.localport>;
        $!localport
    }

    method host(::?CLASS:D: --> Str:_) {
        Rakudo::Deprecations.DEPRECATED:
            'IO::Socket::INET.remote-address.literal',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::INET.host>;
        $!host
    }

    method port(::?CLASS:D: --> Int:_) {
        Rakudo::Deprecations.DEPRECATED:
            'IO::Socket::INET.remote-address.port',
            '2020.FUTURE', # FIXME
            '6.e',
            :what<IO::Socket::INET.port>;
        $!port
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
