my enum DNSType (
    DNS_TYPE_A          => 1,
    DNS_TYPE_NS         => 2,
    DNS_TYPE_MD         => 3,
    DNS_TYPE_MF         => 4,
    DNS_TYPE_CNAME      => 5,
    DNS_TYPE_SOA        => 6,
    DNS_TYPE_MB         => 7,
    DNS_TYPE_MG         => 8,
    DNS_TYPE_MR         => 9,
    DNS_TYPE_NULL       => 10,
    DNS_TYPE_WKS        => 11,
    DNS_TYPE_PTR        => 12,
    DNS_TYPE_HINFO      => 13,
    DNS_TYPE_MINFO      => 14,
    DNS_TYPE_MX         => 15,
    DNS_TYPE_TXT        => 16,
    DNS_TYPE_RP         => 17,
    DNS_TYPE_AFSDB      => 18,
    DNS_TYPE_X25        => 19,
    DNS_TYPE_ISDN       => 20,
    DNS_TYPE_RT         => 21,
    DNS_TYPE_NSAP       => 22,
    DNS_TYPE_NSAP_PTR   => 23,
    DNS_TYPE_SIG        => 24,
    DNS_TYPE_KEY        => 25,
    DNS_TYPE_PX         => 26,
    DNS_TYPE_GPOS       => 27,
    DNS_TYPE_AAAA       => 28,
    DNS_TYPE_LOC        => 29,
    DNS_TYPE_NXT        => 30,
    DNS_TYPE_EID        => 31,
    DNS_TYPE_NIMLOC     => 32,
    DNS_TYPE_SRV        => 33,
    DNS_TYPE_ATMA       => 34,
    DNS_TYPE_NAPTR      => 35,
    DNS_TYPE_KX         => 36,
    DNS_TYPE_CERT       => 37,
    DNS_TYPE_A6         => 38,
    DNS_TYPE_DNAME      => 39,
    DNS_TYPE_SINK       => 40,
    DNS_TYPE_OPT        => 41,
    DNS_TYPE_APL        => 42,
    DNS_TYPE_DS         => 43,
    DNS_TYPE_SSHFP      => 44,
    DNS_TYPE_IPSECKEY   => 45,
    DNS_TYPE_RRSIG      => 46,
    DNS_TYPE_NSEC       => 47,
    DNS_TYPE_DNSKEY     => 48,
    DNS_TYPE_DHCID      => 49,
    DNS_TYPE_NSEC3      => 50,
    DNS_TYPE_NSEC3PARAM => 51,
    DNS_TYPE_TLSA       => 52,
    DNS_TYPE_SMIMEA     => 53,
    DNS_TYPE_HIP        => 55,
    DNS_TYPE_NINFO      => 56,
    DNS_TYPE_RKEY       => 57,
    DNS_TYPE_TALINK     => 58,
    DNS_TYPE_CDS        => 59,
    DNS_TYPE_CDNSKEY    => 60,
    DNS_TYPE_OPENPGPKEY => 61,
    DNS_TYPE_CSYNC      => 62,
    DNS_TYPE_ZONEMD     => 63,
    DNS_TYPE_SVCB       => 64,
    DNS_TYPE_HTTPS      => 65,
    DNS_TYPE_SPF        => 99,
    DNS_TYPE_UINFO      => 100,
    DNS_TYPE_UID        => 101,
    DNS_TYPE_GID        => 102,
    DNS_TYPE_UNSPEC     => 103,
    DNS_TYPE_NID        => 104,
    DNS_TYPE_L32        => 105,
    DNS_TYPE_L64        => 106,
    DNS_TYPE_LP         => 107,
    DNS_TYPE_EUI48      => 108,
    DNS_TYPE_EUI64      => 109,
    DNS_TYPE_TKEY       => 249,
    DNS_TYPE_TSIG       => 250,
    DNS_TYPE_IXFR       => 251,
    DNS_TYPE_AXFR       => 252,
    DNS_TYPE_MAILB      => 253,
    DNS_TYPE_MAILA      => 254,
    DNS_TYPE_ANY        => 255,
    DNS_TYPE_URI        => 256,
    DNS_TYPE_CAA        => 257,
    DNS_TYPE_AVC        => 258,
    DNS_TYPE_DOA        => 259,
    DNS_TYPE_AMTRELAY   => 260,
    DNS_TYPE_TA         => 32768,
    DNS_TYPE_DLV        => 32769,
);

my enum DNSClass (
    DNS_CLASS_IN   => 1,
    # DNS_CLASS_CH   => 3,
    # DNS_CLASS_HS   => 4,
    # DNS_CLASS_NONE => 254,
    # DNS_CLASS_ANY  => 255,
);

my class IO::Resolver::Stub is IO::Resolver {
    my constant Port = IO::Address::IP::Port;

    has Mu $!VM-resolver is required;

    submethod BUILD(::?CLASS:D: :@name-servers where .all ~~ IO::Address::IP:D, Port :$port = 53 --> Nil) {
        my Mu $name-servers := nqp::list;
        nqp::push($name-servers, nqp::getattr(nqp::decont($_), IO::Address, '$!VM-address')) for @name-servers;
        $!VM-resolver := nqp::dnsresolver($name-servers, nqp::decont_i($port), blob8.^pun);
    }

    class ResourceRecord {
        has Str:D $.domain-name is required;
        has Int:D $!type        is required is built;
        has Int:D $!class       is required is built;
        has Int:D $.ttl         is required;

        method type(::?CLASS:D: --> DNSType:_) { DNSType($!type) }

        method class(::?CLASS:D: --> DNSClass:_) { DNSClass($!class) }

        method data(::?CLASS:D: --> Blob:D) { ... }

        multi method gist(::?CLASS:D: --> Str:D) {
            my DNSType:_  $type       := self.type;
            my Str:D      $type-name  := $type.DEFINITE ?? $type.key.substr(9) !! "TYPE$!type";
            my DNSClass:_ $class      := self.class;
            my Str:D      $class-name := $class.DEFINITE ?? $class.key.substr(10) !! "CLASS$!class";
            "$!domain-name\. $!ttl $class-name $type-name"
        }

        my role Data[DNS_TYPE_A] {
            has IO::Address::IPv4:D $.address is required;

            method data(::?CLASS:D: --> Blob:D) { $!address.raw }

            multi method gist(::?CLASS:D: --> Str:D) {
                "&callsame() $!address.presentation()"
            }
        }
        my role Data[DNSType:_] { # Fallback (RFC 3597).
            has Blob:D $.data is required;

            multi method gist(::?CLASS:D: --> Str:D) {
                join ' ', callsame, '\#', $!data.bytes, $!data.contents.fmt: '%02X', ''
            }
        }

        method ^parameterize(::?CLASS:U $this is raw, DNSType:_ $type --> ::?CLASS:U) {
            my ::?CLASS:U $mixin := self.mixin: $this, Data.^parameterize: $type;
            $mixin.^set_name: self.name($this) ~ "[$type]";
            $mixin
        }
    }

    my class QueryTappable does Tappable {
        my class Query is repr<AsyncTask> { }

        has IO::Resolver::Stub:D $!resolver    is required;
        has Scheduler:D          $!scheduler   is required;
        has Str:D                $!domain-name is required;
        has DNSType:D            $!type        is required;
        has DNSClass:D           $!class       is required;

        submethod BUILD(::?CLASS:_: :$!resolver!, :$!scheduler!, :$!domain-name!, :$!type!, :$!class! --> Nil) { }

        method tap(::?CLASS:D: &emit, &done, &quit, &tap --> Tap:D) {
            my Query:D $query := nqp::asyncdnsquery(
              nqp::getattr(nqp::decont($!resolver), IO::Resolver::Stub, '$!VM-resolver'),
              $!scheduler.queue(:hint-affinity),
              -> Str:_ $error is raw, +@answer is raw {
                  with $error {
                      quit X::AdHoc.new: payload => $error;
                  }
                  else {
                      emit hllize-rr DNSType(.[0]), |$_ for @answer;
                  }
                  done;
              },
              nqp::decont_s($!domain-name),
              nqp::decont_i($!type.value),
              nqp::decont_i($!class.value),
              Query);

            tap my Tap:D $tap = Tap.new; # Tap.new({ nqp::cancel($query) })
            $tap
        }

        proto sub hllize-rr(
            DNSType:_  $typed-type,
            Int:D      $type,
            Int:D      $class,
            Int:D      $ttl,
            Str:D      $domain-name,
                      +,
            --> ResourceRecord:D
        ) {
            ResourceRecord[$typed-type].new: :$domain-name, :$type, :$class, :$ttl, |Map.new({*})
        }
        multi sub hllize-rr(DNS_TYPE_A;; \, \, \, \, Mu $VM-address is raw) {
            address => nqp::p6bindattrinvres(
              nqp::create(IO::Address::IPv4), IO::Address, '$!VM-address', $VM-address)
        }
        multi sub hllize-rr(DNSType:_;; \, \, \, \, Blob:D $data) {
            :$data
        }

        method live(::?CLASS:_: --> False)  { }
        method sane(::?CLASS:_: --> True)   { }
        method serial(::?CLASS:_: --> True) { }
    }

    method query(
        ::?CLASS:D   $resolver:
        Str:D        $domain-name,
        DNSType:D    $type,
        # DNSClass:D  $class = DNS_CLASS_IN,
        Scheduler:D :$scheduler = $*SCHEDULER,
        --> Supply:D
    ) {
        Supply.new: QueryTappable.new: :$resolver, :$scheduler, :$domain-name, :$type, :class(DNS_CLASS_IN)
    }
}

Rakudo::Internals.REGISTER-DYNAMIC: '$*RESOLVER', {
    PROCESS::<$RESOLVER> := IO::Resolver::Stub.new;
}, '6.e';
