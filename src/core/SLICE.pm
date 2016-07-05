#===============================================================================
#
# This file has been generated by tools/build/makeSLICE.pl6
# on 2016-07-05T10:56:19.135706Z.
#
# Please do *NOT* make changes to this file, as they will be lost
# whenever this file is generated again.
#
#===============================================================================

# internal 1 element list access with adverbs
sub SLICE_ONE_LIST(\SELF,$one,$key,$value,%adv) {
    my Mu $d := nqp::clone(nqp::getattr(%adv,Map,'$!storage'));
    nqp::bindkey($d,nqp::unbox_s($key),nqp::decont($value));

    sub HANDLED($key) {
        nqp::if(
          nqp::existskey($d,nqp::unbox_s($key)),
          nqp::stmts(
            (my $value := nqp::atkey($d,$key)),
            nqp::deletekey($d,$key),
            $value
          ),
          Nil
        )
    }

    my @nogo;
    my \result = do {

        if HANDLED('delete') {            # :delete:*
            if HANDLED('SINK') {            # :delete:SINK
                SELF.DELETE-POS($one,:SINK);
            }
            elsif nqp::elems($d) == 0 {       # :delete
                SELF.DELETE-POS($one);
            }
            elsif nqp::existskey($d,'exists') { # :delete:exists(0|1):*
                my $exists   := HANDLED('exists');
                my $wasthere := SELF.EXISTS-POS($one);
                SELF.DELETE-POS($one);
                if nqp::elems($d) == 0 {          # :delete:exists(0|1)
                    !( $wasthere ?^ $exists )
                }
                elsif nqp::existskey($d,'kv') {   # :delete:exists(0|1):kv(0|1)
                    my $kv := HANDLED('kv');
                    if nqp::elems($d) == 0 {
                        !$kv || $wasthere
                          ?? ( $one, !( $wasthere ?^ $exists ) )
                          !! ();
                    }
                    else {
                        @nogo = <delete exists kv>;
                    }
                }
                elsif nqp::existskey($d,'p') {    # :delete:exists(0|1):p(0|1)
                    my $p := HANDLED('p');
                    if nqp::elems($d) == 0 {
                        !$p || $wasthere
                          ?? Pair.new($one, !($wasthere ?^ $exists) )
                          !! ();
                    }
                    else {
                        @nogo = <delete exists p>;
                    }
                }
                else {
                    @nogo = <delete exists>;
                }
            }
            elsif nqp::existskey($d,'kv') {    # :delete:kv(0|1)
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {
                    !$kv || SELF.EXISTS-POS($one)
                      ?? ( $one, SELF.DELETE-POS($one) )
                      !! ();
                }
                else {
                    @nogo = <delete kv>;
                }
            }
            elsif nqp::existskey($d,'p') {     # :delete:p(0|1)
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {
                    !$p || SELF.EXISTS-POS($one)
                      ?? Pair.new($one, SELF.DELETE-POS($one))
                      !! ();
                }
                else {
                    @nogo = <delete p>;
                }
            }
            elsif nqp::existskey($d,'k') {     # :delete:k(0|1)
                my $k := HANDLED('k');
                if nqp::elems($d) == 0 {
                    !$k || SELF.EXISTS-POS($one)
                      ?? do { SELF.DELETE-POS($one); $one }
                      !! ();
                }
                else {
                    @nogo = <delete k>;
                }
            }
            elsif nqp::existskey($d,'v') {     # :delete:v(0|1)
                my $v := HANDLED('v');
                if nqp::elems($d) == 0 {
                    !$v || SELF.EXISTS-POS($one)
                      ?? SELF.DELETE-POS($one)
                      !! ();
                }
                else {
                    @nogo = <delete v>;
                }
            }
            else {
                @nogo = <delete>;
            }
        }
        elsif nqp::existskey($d,'exists') {  # :!delete?:exists(0|1):*
            my $exists  := HANDLED('exists');
            my $wasthere = SELF.EXISTS-POS($one);
            if nqp::elems($d) == 0 {           # :!delete?:exists(0|1)
                !( $wasthere ?^ $exists )
            }
            elsif nqp::existskey($d,'kv') {    # :!delete?:exists(0|1):kv(0|1)
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {
                    !$kv || $wasthere
                      ?? ( $one, !( $wasthere ?^ $exists ) )
                      !! ();
                }
                else {
                    @nogo = <exists kv>;
                }
            }
            elsif nqp::existskey($d,'p') {     # :!delete?:exists(0|1):p(0|1)
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {
                    !$p || $wasthere
                      ?? Pair.new($one, !( $wasthere ?^ $exists ))
                      !! ();
                }
                else {
                    @nogo = <exists p>;
                }
            }
            else {
                @nogo = <exists>;
            }
        }
        elsif nqp::existskey($d,'kv') {      # :!delete?:kv(0|1):*
            my $kv := HANDLED('kv');
            if nqp::elems($d) == 0 {           # :!delete?:kv(0|1)
                !$kv || SELF.EXISTS-POS($one)
                  ?? ($one, SELF.AT-POS($one))
                  !! ();
            }
            else {
                @nogo = <kv>;
            }
        }
        elsif nqp::existskey($d,'p') {       # :!delete?:p(0|1):*
            my $p := HANDLED('p');
            if nqp::elems($d) == 0 {           # :!delete?:p(0|1)
                !$p || SELF.EXISTS-POS($one)
                  ?? Pair.new($one, SELF.AT-POS($one))
                  !! ();
            }
            else {
                @nogo = <p>;
            }
        }
        elsif nqp::existskey($d,'k') {       # :!delete?:k(0|1):*
            my $k := HANDLED('k');
            if nqp::elems($d) == 0 {           # :!delete?:k(0|1)
                !$k || SELF.EXISTS-POS($one)
                  ?? $one
                  !! ();
            }
            else {
                @nogo = <k>;
            }
        }
        elsif nqp::existskey($d,'v') {       # :!delete?:v(0|1):*
            my $v := HANDLED('v');             # :!delete?:v(0|1)
            if nqp::elems($d) == 0 {
                !$v || SELF.EXISTS-POS($one)
                  ?? SELF.AT-POS($one)
                  !! ();
            }
            else {
                @nogo = <v>;
            }
        }
        elsif nqp::elems($d) == 0 {           # :!delete
            SELF.AT-POS($one);
        }
    }

    @nogo || nqp::elems($d)
      ?? SLICE_HUH( SELF, @nogo, $d, %adv )
      !! result;
} #SLICE_ONE_LIST

# internal >1 element list access with adverbs
sub SLICE_MORE_LIST(\SELF,$more,$key,$value,%adv) {
    my Mu $d := nqp::clone(nqp::getattr(%adv,Map,'$!storage'));
    nqp::bindkey($d,nqp::unbox_s($key),nqp::decont($value));

    sub HANDLED($key) {
        nqp::if(
          nqp::existskey($d,nqp::unbox_s($key)),
          nqp::stmts(
            (my $value := nqp::atkey($d,$key)),
            nqp::deletekey($d,$key),
            $value
          ),
          Nil
        )
    }

    my @nogo;
    my \result = do {

        if HANDLED('delete') {            # :delete:*
            if HANDLED('SINK') {            # :delete:SINK
                SELF.DELETE-POS($_,:SINK) for $more.cache;
                Nil;
            }
            elsif nqp::elems($d) == 0 {       # :delete
                $more.cache.flatmap( { SELF.DELETE-POS($_) } ).eager.list;
            }
            elsif nqp::existskey($d,'exists') { # :delete:exists(0|1):*
                my $exists := HANDLED('exists');
                my $wasthere; # no need to initialize every iteration of map
                if nqp::elems($d) == 0 {          # :delete:exists(0|1)
                    $more.cache.flatmap( {
                        SELF.DELETE-POS($_) if $wasthere = SELF.EXISTS-POS($_);
                        !( $wasthere ?^ $exists );
                    } ).eager.list;
                }
                elsif nqp::existskey($d,'kv') { # :delete:exists(0|1):kv(0|1):*
                    my $kv := HANDLED('kv');
                    if nqp::elems($d) == 0 {      # :delete:exists(0|1):kv(0|1)
                        $more.cache.flatmap( {
                            SELF.DELETE-POS($_) if $wasthere = SELF.EXISTS-POS($_);
                            next unless !$kv || $wasthere;
                            ($_, !( $wasthere ?^ $exists ));
                        } ).flat.eager.list;
                    }
                    else {
                        @nogo = <delete exists kv>;
                    }
                }
                elsif nqp::existskey($d,'p') {  # :delete:exists(0|1):p(0|1):*
                    my $p := HANDLED('p');
                    if nqp::elems($d) == 0 {      # :delete:exists(0|1):p(0|1)
                        $more.cache.flatmap( {
                            SELF.DELETE-POS($_) if $wasthere = SELF.EXISTS-POS($_);
                            next unless !$p || $wasthere;
                            Pair.new($_,!($wasthere ?^ $exists));
                        } ).eager.list;
                    }
                    else {
                        @nogo = <delete exists p>;
                    }
                }
                else {
                    @nogo = <delete exists>;
                }
            }
            elsif nqp::existskey($d,'kv') {     # :delete:kv(0|1):*
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {          # :delete:kv(0|1)
                    $kv
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-POS($_);
                             ( $_, SELF.DELETE-POS($_) );
                         } ).flat.eager.list
                      !! $more.cache.flatmap( {
                             ( $_, SELF.DELETE-POS($_) )
                         } ).flat.eager.list;
                }
                else {
                    @nogo = <delete kv>;
                }
            }
            elsif nqp::existskey($d,'p') {      # :delete:p(0|1):*
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {          # :delete:p(0|1)
                    $p
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-POS($_);
                             Pair.new($_, SELF.DELETE-POS($_));
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             Pair.new($_, SELF.DELETE-POS($_))
                         } ).eager.list;
                }
                else {
                    @nogo = <delete p>;
                }
            }
            elsif nqp::existskey($d,'k') {     # :delete:k(0|1):*
                my $k := HANDLED('k');
                if nqp::elems($d) == 0 {          # :delete:k(0|1)
                    $k
                      ?? $more.cache.flatmap( {
                             nqp::if(
                               SELF.EXISTS-POS($_),
                               nqp::stmts(
                                 SELF.DELETE-POS($_),
                                 $_
                               ),
                               next
                             )
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             SELF.DELETE-POS($_); $_
                         } ).eager.list;
                }
                else {
                    @nogo = <delete k>;
                }
            }
            elsif nqp::existskey($d,'v') {      # :delete:v(0|1):*
                my $v := HANDLED('v');
                if nqp::elems($d) == 0 {          # :delete:v(0|1)
                    $v
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-POS($_);
                             SELF.DELETE-POS($_);
                     } ).eager.list
                      !! $more.cache.flatmap( {
                             SELF.DELETE-POS($_)
                     } ).eager.list;
                }
                else {
                    @nogo = <delete v>;
                }
            }
            else {
                @nogo = <delete>;
            }
        }
        elsif nqp::existskey($d,'exists') { # :!delete?:exists(0|1):*
            my $exists := HANDLED('exists');
            if nqp::elems($d) == 0 {          # :!delete?:exists(0|1)
                $more.cache.flatmap({ !( SELF.EXISTS-POS($_) ?^ $exists ) }).eager.list;
            }
            elsif nqp::existskey($d,'kv') {   # :!delete?:exists(0|1):kv(0|1):*
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {        # :!delete?:exists(0|1):kv(0|1)
                    $kv
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-POS($_);
                             ( $_, $exists );
                         } ).flat.eager.list
                      !! $more.cache.flatmap( {
                             ( $_, !( SELF.EXISTS-POS($_) ?^ $exists ) )
                         } ).flat.eager.list;
                }
                else {
                    @nogo = <exists kv>;
                }
            }
            elsif nqp::existskey($d,'p') {  # :!delete?:exists(0|1):p(0|1):*
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {      # :!delete?:exists(0|1):p(0|1)
                    $p
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-POS($_);
                             Pair.new( $_, $exists );
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             Pair.new( $_, !( SELF.EXISTS-POS($_) ?^ $exists ) )
                         } ).eager.list;
                }
                else {
                    @nogo = <exists p>;
                }
            }
            else {
                @nogo = <exists>;
            }
        }
        elsif nqp::existskey($d,'kv') {     # :!delete?:kv(0|1):*
            my $kv := HANDLED('kv');
            if nqp::elems($d) == 0 {          # :!delete?:kv(0|1)
                $kv
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-POS($_);
                         $_, SELF.AT-POS($_);
                     } ).flat.eager.list
                  !! $more.cache.flatmap( {
                         $_, SELF.AT-POS($_)
                     } ).flat.eager.list;
            }
            else {
                @nogo = <kv>;
            }
        }
        elsif nqp::existskey($d,'p') {      # :!delete?:p(0|1):*
            my $p := HANDLED('p');
            if nqp::elems($d) == 0 {          # :!delete?:p(0|1)
                $p
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-POS($_);
                         Pair.new($_, SELF.AT-POS($_));
                     } ).eager.list
                  !! $more.cache.flatmap( {
                         Pair.new( $_, SELF.AT-POS($_) )
                     } ).eager.list;
            }
            else {
                @nogo = <p>
            }
        }
        elsif nqp::existskey($d,'k') {      # :!delete?:k(0|1):*
            my $k := HANDLED('k');
            if nqp::elems($d) == 0 {          # :!delete?:k(0|1)
                $k
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-POS($_);
                         $_;
                     } ).eager.list
                  !! $more.cache.flat.eager.list;
            }
            else {
                @nogo = <k>;
            }
        }
        elsif nqp::existskey($d,'v') {      # :!delete?:v(0|1):*
            my $v := HANDLED('v');
            if nqp::elems($d) == 0 {          # :!delete?:v(0|1)
                $v
                  ??  $more.cache.flatmap( {
                          next unless SELF.EXISTS-POS($_);
                          SELF.AT-POS($_);
                      } ).eager.list
                  !!  $more.cache.flatmap( {
                          SELF.AT-POS($_)
                      } ).eager.list;
            }
            else {
                @nogo = <v>;
            }
        }
        elsif nqp::elems($d) == 0 {         # :!delete
            $more.cache.flatmap( { SELF.AT-POS($_) } ).eager.list;
        }
    }

    @nogo || nqp::elems($d)
      ?? SLICE_HUH( SELF, @nogo, $d, %adv )
      !! result;
} #SLICE_MORE_LIST


# internal 1 element hash access with adverbs
sub SLICE_ONE_HASH(\SELF,$one,$key,$value,%adv) {
    my Mu $d := nqp::clone(nqp::getattr(%adv,Map,'$!storage'));
    nqp::bindkey($d,nqp::unbox_s($key),nqp::decont($value));

    sub HANDLED($key) {
        nqp::if(
          nqp::existskey($d,nqp::unbox_s($key)),
          nqp::stmts(
            (my $value := nqp::atkey($d,$key)),
            nqp::deletekey($d,$key),
            $value
          ),
          Nil
        )
    }

    my @nogo;
    my \result = do {

        if HANDLED('delete') {            # :delete:*
            if HANDLED('SINK') {            # :delete:SINK
                SELF.DELETE-KEY($one,:SINK);
            }
            elsif nqp::elems($d) == 0 {       # :delete
                SELF.DELETE-KEY($one);
            }
            elsif nqp::existskey($d,'exists') { # :delete:exists(0|1):*
                my $exists   := HANDLED('exists');
                my $wasthere := SELF.EXISTS-KEY($one);
                SELF.DELETE-KEY($one);
                if nqp::elems($d) == 0 {          # :delete:exists(0|1)
                    !( $wasthere ?^ $exists )
                }
                elsif nqp::existskey($d,'kv') {   # :delete:exists(0|1):kv(0|1)
                    my $kv := HANDLED('kv');
                    if nqp::elems($d) == 0 {
                        !$kv || $wasthere
                          ?? ( $one, !( $wasthere ?^ $exists ) )
                          !! ();
                    }
                    else {
                        @nogo = <delete exists kv>;
                    }
                }
                elsif nqp::existskey($d,'p') {    # :delete:exists(0|1):p(0|1)
                    my $p := HANDLED('p');
                    if nqp::elems($d) == 0 {
                        !$p || $wasthere
                          ?? Pair.new($one, !($wasthere ?^ $exists) )
                          !! ();
                    }
                    else {
                        @nogo = <delete exists p>;
                    }
                }
                else {
                    @nogo = <delete exists>;
                }
            }
            elsif nqp::existskey($d,'kv') {    # :delete:kv(0|1)
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {
                    !$kv || SELF.EXISTS-KEY($one)
                      ?? ( $one, SELF.DELETE-KEY($one) )
                      !! ();
                }
                else {
                    @nogo = <delete kv>;
                }
            }
            elsif nqp::existskey($d,'p') {     # :delete:p(0|1)
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {
                    !$p || SELF.EXISTS-KEY($one)
                      ?? Pair.new($one, SELF.DELETE-KEY($one))
                      !! ();
                }
                else {
                    @nogo = <delete p>;
                }
            }
            elsif nqp::existskey($d,'k') {     # :delete:k(0|1)
                my $k := HANDLED('k');
                if nqp::elems($d) == 0 {
                    !$k || SELF.EXISTS-KEY($one)
                      ?? do { SELF.DELETE-KEY($one); $one }
                      !! ();
                }
                else {
                    @nogo = <delete k>;
                }
            }
            elsif nqp::existskey($d,'v') {     # :delete:v(0|1)
                my $v := HANDLED('v');
                if nqp::elems($d) == 0 {
                    !$v || SELF.EXISTS-KEY($one)
                      ?? SELF.DELETE-KEY($one)
                      !! ();
                }
                else {
                    @nogo = <delete v>;
                }
            }
            else {
                @nogo = <delete>;
            }
        }
        elsif nqp::existskey($d,'exists') {  # :!delete?:exists(0|1):*
            my $exists  := HANDLED('exists');
            my $wasthere = SELF.EXISTS-KEY($one);
            if nqp::elems($d) == 0 {           # :!delete?:exists(0|1)
                !( $wasthere ?^ $exists )
            }
            elsif nqp::existskey($d,'kv') {    # :!delete?:exists(0|1):kv(0|1)
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {
                    !$kv || $wasthere
                      ?? ( $one, !( $wasthere ?^ $exists ) )
                      !! ();
                }
                else {
                    @nogo = <exists kv>;
                }
            }
            elsif nqp::existskey($d,'p') {     # :!delete?:exists(0|1):p(0|1)
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {
                    !$p || $wasthere
                      ?? Pair.new($one, !( $wasthere ?^ $exists ))
                      !! ();
                }
                else {
                    @nogo = <exists p>;
                }
            }
            else {
                @nogo = <exists>;
            }
        }
        elsif nqp::existskey($d,'kv') {      # :!delete?:kv(0|1):*
            my $kv := HANDLED('kv');
            if nqp::elems($d) == 0 {           # :!delete?:kv(0|1)
                !$kv || SELF.EXISTS-KEY($one)
                  ?? ($one, SELF.AT-KEY($one))
                  !! ();
            }
            else {
                @nogo = <kv>;
            }
        }
        elsif nqp::existskey($d,'p') {       # :!delete?:p(0|1):*
            my $p := HANDLED('p');
            if nqp::elems($d) == 0 {           # :!delete?:p(0|1)
                !$p || SELF.EXISTS-KEY($one)
                  ?? Pair.new($one, SELF.AT-KEY($one))
                  !! ();
            }
            else {
                @nogo = <p>;
            }
        }
        elsif nqp::existskey($d,'k') {       # :!delete?:k(0|1):*
            my $k := HANDLED('k');
            if nqp::elems($d) == 0 {           # :!delete?:k(0|1)
                !$k || SELF.EXISTS-KEY($one)
                  ?? $one
                  !! ();
            }
            else {
                @nogo = <k>;
            }
        }
        elsif nqp::existskey($d,'v') {       # :!delete?:v(0|1):*
            my $v := HANDLED('v');             # :!delete?:v(0|1)
            if nqp::elems($d) == 0 {
                !$v || SELF.EXISTS-KEY($one)
                  ?? SELF.AT-KEY($one)
                  !! ();
            }
            else {
                @nogo = <v>;
            }
        }
        elsif nqp::elems($d) == 0 {           # :!delete
            SELF.AT-KEY($one);
        }
    }

    @nogo || nqp::elems($d)
      ?? SLICE_HUH( SELF, @nogo, $d, %adv )
      !! result;
} #SLICE_ONE_HASH

# internal >1 element hash access with adverbs
sub SLICE_MORE_HASH(\SELF,$more,$key,$value,%adv) {
    my Mu $d := nqp::clone(nqp::getattr(%adv,Map,'$!storage'));
    nqp::bindkey($d,nqp::unbox_s($key),nqp::decont($value));

    sub HANDLED($key) {
        nqp::if(
          nqp::existskey($d,nqp::unbox_s($key)),
          nqp::stmts(
            (my $value := nqp::atkey($d,$key)),
            nqp::deletekey($d,$key),
            $value
          ),
          Nil
        )
    }

    my @nogo;
    my \result = do {

        if HANDLED('delete') {            # :delete:*
            if HANDLED('SINK') {            # :delete:SINK
                SELF.DELETE-KEY($_,:SINK) for $more.cache;
                Nil;
            }
            elsif nqp::elems($d) == 0 {       # :delete
                $more.cache.flatmap( { SELF.DELETE-KEY($_) } ).eager.list;
            }
            elsif nqp::existskey($d,'exists') { # :delete:exists(0|1):*
                my $exists := HANDLED('exists');
                my $wasthere; # no need to initialize every iteration of map
                if nqp::elems($d) == 0 {          # :delete:exists(0|1)
                    $more.cache.flatmap( {
                        SELF.DELETE-KEY($_) if $wasthere = SELF.EXISTS-KEY($_);
                        !( $wasthere ?^ $exists );
                    } ).eager.list;
                }
                elsif nqp::existskey($d,'kv') { # :delete:exists(0|1):kv(0|1):*
                    my $kv := HANDLED('kv');
                    if nqp::elems($d) == 0 {      # :delete:exists(0|1):kv(0|1)
                        $more.cache.flatmap( {
                            SELF.DELETE-KEY($_) if $wasthere = SELF.EXISTS-KEY($_);
                            next unless !$kv || $wasthere;
                            ($_, !( $wasthere ?^ $exists ));
                        } ).flat.eager.list;
                    }
                    else {
                        @nogo = <delete exists kv>;
                    }
                }
                elsif nqp::existskey($d,'p') {  # :delete:exists(0|1):p(0|1):*
                    my $p := HANDLED('p');
                    if nqp::elems($d) == 0 {      # :delete:exists(0|1):p(0|1)
                        $more.cache.flatmap( {
                            SELF.DELETE-KEY($_) if $wasthere = SELF.EXISTS-KEY($_);
                            next unless !$p || $wasthere;
                            Pair.new($_,!($wasthere ?^ $exists));
                        } ).eager.list;
                    }
                    else {
                        @nogo = <delete exists p>;
                    }
                }
                else {
                    @nogo = <delete exists>;
                }
            }
            elsif nqp::existskey($d,'kv') {     # :delete:kv(0|1):*
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {          # :delete:kv(0|1)
                    $kv
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-KEY($_);
                             ( $_, SELF.DELETE-KEY($_) );
                         } ).flat.eager.list
                      !! $more.cache.flatmap( {
                             ( $_, SELF.DELETE-KEY($_) )
                         } ).flat.eager.list;
                }
                else {
                    @nogo = <delete kv>;
                }
            }
            elsif nqp::existskey($d,'p') {      # :delete:p(0|1):*
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {          # :delete:p(0|1)
                    $p
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-KEY($_);
                             Pair.new($_, SELF.DELETE-KEY($_));
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             Pair.new($_, SELF.DELETE-KEY($_))
                         } ).eager.list;
                }
                else {
                    @nogo = <delete p>;
                }
            }
            elsif nqp::existskey($d,'k') {     # :delete:k(0|1):*
                my $k := HANDLED('k');
                if nqp::elems($d) == 0 {          # :delete:k(0|1)
                    $k
                      ?? $more.cache.flatmap( {
                             nqp::if(
                               SELF.EXISTS-KEY($_),
                               nqp::stmts(
                                 SELF.DELETE-KEY($_),
                                 $_
                               ),
                               next
                             )
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             SELF.DELETE-KEY($_); $_
                         } ).eager.list;
                }
                else {
                    @nogo = <delete k>;
                }
            }
            elsif nqp::existskey($d,'v') {      # :delete:v(0|1):*
                my $v := HANDLED('v');
                if nqp::elems($d) == 0 {          # :delete:v(0|1)
                    $v
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-KEY($_);
                             SELF.DELETE-KEY($_);
                     } ).eager.list
                      !! $more.cache.flatmap( {
                             SELF.DELETE-KEY($_)
                     } ).eager.list;
                }
                else {
                    @nogo = <delete v>;
                }
            }
            else {
                @nogo = <delete>;
            }
        }
        elsif nqp::existskey($d,'exists') { # :!delete?:exists(0|1):*
            my $exists := HANDLED('exists');
            if nqp::elems($d) == 0 {          # :!delete?:exists(0|1)
                $more.cache.flatmap({ !( SELF.EXISTS-KEY($_) ?^ $exists ) }).eager.list;
            }
            elsif nqp::existskey($d,'kv') {   # :!delete?:exists(0|1):kv(0|1):*
                my $kv := HANDLED('kv');
                if nqp::elems($d) == 0 {        # :!delete?:exists(0|1):kv(0|1)
                    $kv
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-KEY($_);
                             ( $_, $exists );
                         } ).flat.eager.list
                      !! $more.cache.flatmap( {
                             ( $_, !( SELF.EXISTS-KEY($_) ?^ $exists ) )
                         } ).flat.eager.list;
                }
                else {
                    @nogo = <exists kv>;
                }
            }
            elsif nqp::existskey($d,'p') {  # :!delete?:exists(0|1):p(0|1):*
                my $p := HANDLED('p');
                if nqp::elems($d) == 0 {      # :!delete?:exists(0|1):p(0|1)
                    $p
                      ?? $more.cache.flatmap( {
                             next unless SELF.EXISTS-KEY($_);
                             Pair.new( $_, $exists );
                         } ).eager.list
                      !! $more.cache.flatmap( {
                             Pair.new( $_, !( SELF.EXISTS-KEY($_) ?^ $exists ) )
                         } ).eager.list;
                }
                else {
                    @nogo = <exists p>;
                }
            }
            else {
                @nogo = <exists>;
            }
        }
        elsif nqp::existskey($d,'kv') {     # :!delete?:kv(0|1):*
            my $kv := HANDLED('kv');
            if nqp::elems($d) == 0 {          # :!delete?:kv(0|1)
                $kv
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-KEY($_);
                         $_, SELF.AT-KEY($_);
                     } ).flat.eager.list
                  !! $more.cache.flatmap( {
                         $_, SELF.AT-KEY($_)
                     } ).flat.eager.list;
            }
            else {
                @nogo = <kv>;
            }
        }
        elsif nqp::existskey($d,'p') {      # :!delete?:p(0|1):*
            my $p := HANDLED('p');
            if nqp::elems($d) == 0 {          # :!delete?:p(0|1)
                $p
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-KEY($_);
                         Pair.new($_, SELF.AT-KEY($_));
                     } ).eager.list
                  !! $more.cache.flatmap( {
                         Pair.new( $_, SELF.AT-KEY($_) )
                     } ).eager.list;
            }
            else {
                @nogo = <p>
            }
        }
        elsif nqp::existskey($d,'k') {      # :!delete?:k(0|1):*
            my $k := HANDLED('k');
            if nqp::elems($d) == 0 {          # :!delete?:k(0|1)
                $k
                  ?? $more.cache.flatmap( {
                         next unless SELF.EXISTS-KEY($_);
                         $_;
                     } ).eager.list
                  !! $more.cache.flat.eager.list;
            }
            else {
                @nogo = <k>;
            }
        }
        elsif nqp::existskey($d,'v') {      # :!delete?:v(0|1):*
            my $v := HANDLED('v');
            if nqp::elems($d) == 0 {          # :!delete?:v(0|1)
                $v
                  ??  $more.cache.flatmap( {
                          next unless SELF.EXISTS-KEY($_);
                          SELF.AT-KEY($_);
                      } ).eager.list
                  !!  $more.cache.flatmap( {
                          SELF.AT-KEY($_)
                      } ).eager.list;
            }
            else {
                @nogo = <v>;
            }
        }
        elsif nqp::elems($d) == 0 {         # :!delete
            $more.cache.flatmap( { SELF.AT-KEY($_) } ).eager.list;
        }
    }

    @nogo || nqp::elems($d)
      ?? SLICE_HUH( SELF, @nogo, $d, %adv )
      !! result;
} #SLICE_MORE_HASH


# vim: set ft=perl6 nomodifiable :
