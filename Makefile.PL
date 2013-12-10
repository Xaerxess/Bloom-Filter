use strict;
use warnings;

use ExtUtils::MakeMaker;

my %WriteMakefileArgs = (
    NAME => 'Bloom::Filter',
    VERSION_FROM => 'Filter.pm',
    MIN_PERL_VERSION => '5.6.0',
    PREREQ_PM => {
        'Carp' => 0,
        'Digest::SHA' => 0,
        'strict' => 0,
        'warnings' => 0,
    },
    ABSTRACT_FROM => 'Filter.pm',
    AUTHOR => 'Maciej Ceglowski <maciej@ceglowski.com>',
    LICENSE => 'gpl',
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url => 'git://github.com/Xaerxess/Bloom-Filter.git',
                web => 'https://github.com/Xaerxess/Bloom-Filter',
            },
            bugtracker => {
                web => 'https://rt.cpan.org/Dist/Display.html?Name=Bloom-Filter',
            },
        },
    },
    test => {
        TESTS => "t/*.t"
    },
);

unless (eval { ExtUtils::MakeMaker->VERSION(6.48) }) {
    delete $WriteMakefileArgs{MIN_PERL_VERSION};
}

unless (eval { ExtUtils::MakeMaker->VERSION(6.46) }) {
    delete $WriteMakefileArgs{META_MERGE};
}

unless (eval { ExtUtils::MakeMaker->VERSION(6.31) }) {
    delete $WriteMakefileArgs{LICENSE};
}

WriteMakefile(%WriteMakefileArgs);
