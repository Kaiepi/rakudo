my class IO::Socket::INET does IO::Socket {
    has Int  $.backlog;
    has Bool $.listening;

    # Create a new socket that listens on an explicit IP address
    multi method new(
        Bool:D            :listen($listening)! where ?*,
        IO::Address::IP:D :$address!,
        SocketFamily:D    :$family             = $address.family.value,
        SocketType:D      :$type               = SOCK_STREAM,
        SocketProtocol:D  :$protocol           = IPPROTO_ANY,
                          *%rest
    ) {
        self.bless(:$family, :$type, :$protocol, :$listening, |%rest)!LISTEN-DIRECT($address)
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
        Bool:D           :listen($listening)! where ?*,
        Str              :$localhost,
        Int              :$localport,
        SocketFamily:D   :$family             = PF_UNSPEC,
        SocketType:D     :$type               = SOCK_STREAM,
        SocketProtocol:D :$protocol           = IPPROTO_ANY,
        IO::Resolver:D   :$resolver           = $*RESOLVER,
        Str:D            :$method             = 'resolve',
                         *%rest,
        --> IO::Socket::INET:D
    ) {
        self.bless(
            :$family, :$type, :$protocol, :$listening, |%rest
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
        }
        else {
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
        }
        self
    }

    # Open new connection to socket on an explicit IP address
    multi method new(
        IO::Address::IP:D :$address!,
        SocketFamily:D    :$family    = $address.family.value,
        SocketType:D      :$type      = SOCK_STREAM,
        SocketProtocol:D  :$protocol  = IPPROTO_ANY,
                          *%rest
    ) {
        self.bless(:$family, :$type, :$protocol, |%rest)!CONNECT-DIRECT($address)
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
        Str:D            :$host!,
        Int              :$port,
        SocketFamily:D   :$family   = PF_UNSPEC,
        SocketType:D     :$type     = SOCK_STREAM,
        SocketProtocol:D :$protocol = IPPROTO_ANY,
        IO::Resolver:D   :$resolver = $*RESOLVER,
        Str:D            :$method   = 'lookup',
                         *%rest,
        --> IO::Socket::INET:D
    ) {
        self.bless(
            :$family, :$type, :$protocol, |%rest
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
        }
        else {
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
        }
        self
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
        self.new: :$host, :$port, :$family, :$resolver, :$method
    }

    proto method listen(|) {*}
    multi method listen(
        ::?CLASS:U:
        IO::Address::IP:D  $address,
        SocketFamily:D    :$family   = $address.family,
        --> ::?CLASS:D
    ) {
        self.new: :listen, :$address, :$family
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
        self.new: :listen, :$localhost, :$localport, :$family, :$resolver, :$method
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
}

# vim: expandtab shiftwidth=4
