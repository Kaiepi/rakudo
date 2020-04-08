use v6;
use Test;

plan 1;

# TODO: Tests for the rest of Metamodel::Primitives.

subtest 'parameterization', {
    plan 6;

    my class ParametricHOW does Metamodel::Naming {
        # The work required for creating types is handled outside of here.
    }

    my class ParameterizedHOW does Metamodel::Naming {
        has @!parameters is List is built(:bind);

        method new_type(::?CLASS:_: @parameters, Str:D :$name! --> Mu) {
            my ::?CLASS:D $meta := self.bless: :@parameters;
            my Mu         $obj  := Metamodel::Primitives.create_type: $meta, 'Uninstantiable';
            $meta.set_name: $obj, $name;
            $obj
        }

        method parameters(::?CLASS:D: Mu) { @!parameters }
    }

    my Mu $parametric := Metamodel::Primitives.create_type: ParametricHOW.new, 'Uninstantiable';
    $parametric.^set_name: 'Parametric'; # Eases debugging.
    lives-ok {
        Metamodel::Primitives.set_parameterizer: $parametric, -> Mu \obj, @parameters {
            my Str:D $name = 'Parameterized';
            ParameterizedHOW.new_type: @parameters, :$name
        }
    }, 'can set the parameterizer for a metaobject';

    my Mu $parameterized := Nil;
    my Mu $parameter     .= new; # Intentionally containerized with Scalar.
    lives-ok {
        $parameterized := Metamodel::Primitives.parameterize_type: $parametric, $parameter
    }, 'can parameterize metaobjects';
    cmp-ok $parameterized.^parameters.[0], &[=:=], $parameter,
      'type parameters passed to the parameterizer for a metaobject keep their original containers';
    cmp-ok Metamodel::Primitives.type_parameterized($parameterized), &[=:=], $parametric,
      'can get the parametric type of the result of a parameterization';
    cmp-ok Metamodel::Primitives.type_parameters($parameterized).[0], &[=:=], $parameter,
      'can get the type parameters of the result of a parameterization';
    cmp-ok Metamodel::Primitives.type_parameter_at($parameterized, 0), &[=:=], $parameter,
      'can get a specific type parameter of the result of a parameterization';
};

# vim: ft=perl6 sw=4 ts=4 sts=4 et
