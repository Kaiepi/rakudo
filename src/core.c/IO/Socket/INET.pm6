my class IO::Socket::INET does IO::Socket {
    my module PIO {
        constant MIN_PORT       = 0;
        constant MAX_PORT       = 65_535; # RFC 793: TCP/UDP port limit
    }

    has Str  $.host;
    has Int  $.port;
    has Str  $.localhost;
    has Int  $.localport;
    has Int  $.backlog;
    has Bool $.listening;
    has      $.family     = nqp::const::ADDRESS_FAMILY_UNSPEC;
    has      $.type       = nqp::const::ADDRESS_TYPE_STREAM;
    has      $.proto      = nqp::const::ADDRESS_PROTOCOL_ANY;

    # XXX: this could be a bit smarter about how it deals with unspecified
    # families...
    my sub split-host-port(:$host is copy, :$port is copy, :$family) {
        if ($host) {
            my ($split-host, $split-port) = $family == nqp::const::ADDRESS_FAMILY_INET6
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
        Bool   :$listen! where .so,
        Str    :$localhost is copy,
        Int    :$localport is copy,
        Int    :$family where {
                $family == nqp::const::ADDRESS_FAMILY_UNSPEC
             || $family == nqp::const::ADDRESS_FAMILY_INET
             || $family == nqp::const::ADDRESS_FAMILY_INET6
             || $family == nqp::const::ADDRESS_FAMILY_UNIX
        } = nqp::const::ADDRESS_FAMILY_UNSPEC,
               *%rest,
        --> IO::Socket::INET:D) {

        ($localhost, $localport) = (
            split-host-port :host($localhost), :port($localport), :$family
        orelse fail $_) unless $family == nqp::const::ADDRESS_FAMILY_UNIX;

        #TODO: Learn what protocols map to which socket types and then determine which is needed.
        self.bless(
            :$localhost,
            :$localport,
            :$family,
            :listening($listen),
            |%rest,
        )!initialize()
    }

    # Open new connection to socket on $host:$port
    multi method new(
        Str:D :$host! is copy,
        Int   :$port is copy,
        Int   :$family where {
               $family == nqp::const::ADDRESS_FAMILY_UNSPEC
            || $family == nqp::const::ADDRESS_FAMILY_INET
            || $family == nqp::const::ADDRESS_FAMILY_INET6
            || $family == nqp::const::ADDRESS_FAMILY_UNIX
        } = nqp::const::ADDRESS_FAMILY_UNSPEC,
              *%rest,
        --> IO::Socket::INET:D) {

        ($host, $port) = split-host-port(
            :$host,
            :$port,
            :$family,
        ) unless $family == nqp::const::ADDRESS_FAMILY_UNIX;

        # TODO: Learn what protocols map to which socket types and then determine which is needed.
        self.bless(
            :$host,
            :$port,
            :$family,
            |%rest,
        )!initialize()
    }

    # Fail if no valid parameters are passed
    multi method new() {
        fail "Nothing given for new socket to connect or bind to. "
            ~ "Invalid arguments to .new?";
    }

    method !initialize() {
        my $PIO := nqp::socket($!listening ?? 10 !! 0);

        # Quoting perl5's SIO::INET:
        # If Listen is defined then a listen socket is created, else if the socket type,
        # which is derived from the protocol, is SOCK_STREAM then connect() is called.
        if $!listening || $!localhost || $!localport {
            if $!family == nqp::const::ADDRESS_FAMILY_UNIX {
                my IO::Address::UNIX:D $address := IO::Address::UNIX.new:
                    $!localhost,
                    type     => SocketType($!type),
                    protocol => ProtocolType($!proto);
                nqp::bindsock($PIO,
                    nqp::unbox_i($!family), nqp::unbox_i($!type), nqp::unbox_i($!proto),
                    nqp::getattr($address, $address.WHAT, '$!VM-address'),
                    nqp::unbox_i($!backlog || 128));
            }
            else {
                my Iterable:D $addresses := $*RESOLVER.resolve:
                    $!localhost || '0.0.0.0', $!localport || 0,
                    family   => ProtocolFamily($!family),
                    type     => SocketType($!type),
                    protocol => ProtocolType($!proto),
                    passive  => True;
                &*CONNECT($addresses, sub (IO::Address:D $address) {
                    nqp::bindsock($PIO,
                        nqp::unbox_i(+$address.family), nqp::unbox_i(+$address.type), nqp::unbox_i(+$address.protocol),
                        nqp::getattr(nqp::decont($address), $address.WHAT, '$!VM-address'),
                        nqp::unbox_i($!backlog || 128))
                });
            }
        }

        if $!listening {
#?if !js
            $!localport = nqp::getport($PIO)
                  unless $!localport || ($!family == nqp::const::ADDRESS_FAMILY_UNIX);
#?endif
        }
        # XXX: Compiler bugs a-plenty if you make the two following elsifs one elsif with
        # an if block inside it!
        elsif $!type == nqp::const::ADDRESS_TYPE_STREAM && $!family == nqp::const::ADDRESS_FAMILY_UNIX {
            my IO::Address::UNIX:D $address := IO::Address::UNIX.new:
                $!host,
                type     => SocketType($!type),
                protocol => ProtocolType($!proto);
            nqp::connect($PIO,
                nqp::unbox_i($!family), nqp::unbox_i($!type), nqp::unbox_i($!proto),
                nqp::getattr($address, $address.WHAT, '$!VM-address'));
        }
        elsif $!type == nqp::const::ADDRESS_TYPE_STREAM {
            my Iterable:D $addresses := $*RESOLVER.resolve:
                $!host, $!port,
                family   => ProtocolFamily($!family),
                type     => SocketType($!type),
                protocol => ProtocolType($!proto),
                passive  => True; # For the sake of compatibility with older compiler releases.
            &*CONNECT($addresses, sub (IO::Address:D $address) {
                nqp::connect($PIO,
                    nqp::unbox_i(+$address.family), nqp::unbox_i(+$address.type), nqp::unbox_i(+$address.protocol),
                    nqp::getattr(nqp::decont($address), $address.WHAT, '$!VM-address'))
            });
        }

        nqp::bindattr(self, $?CLASS, '$!PIO', $PIO);
        self;
    }

    method connect(IO::Socket::INET:U: Str() $host, Int() $port, ProtocolFamily:D :$family = PF_UNSPEC) {
        self.new(:$host, :$port, :family($family.value))
    }

    method listen(IO::Socket::INET:U: Str() $localhost, Int() $localport, ProtocolFamily:D :$family = PF_UNSPEC) {
        self.new(:$localhost, :$localport, :family($family.value), :listen)
    }

    method accept() {
        # A solution as proposed by moritz
        my $new_sock := $?CLASS.bless(:$!family, :$!proto, :$!type, :$!nl-in);
        nqp::bindattr($new_sock, $?CLASS, '$!PIO',
            nqp::accept(nqp::getattr(self, $?CLASS, '$!PIO'))
        );
        return $new_sock;
    }
}

# vim: expandtab shiftwidth=4
