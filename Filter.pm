package Bloom::Filter;

use strict;
use warnings;
use Carp;
use Digest::SHA1 qw/sha1 sha1_base64/;

our $VERSION = '0.01';

=head1 NAME

=over 

=item new %PARAMS

Create a brand new instance.  Allowable params are C<error_rate>, C<min_length>.

=cut

sub new {
	my ( $class, %params ) = @_;

	bless {  
			 error_rate => 0.001, 
		     min_length => 20, 
		     filter_length => 20,
			 %params, 
			 keys => {}
		  }, $class;
}


=back

=head1 PUBLIC METHODS

=over 

=item add @EMAIL

Adds email addresses to the filter.  You can either add email addresses 
directly, or add the output of a sha1_base64 hash.  

=cut

sub add {
	my ( $self, @addresses ) = @_;

	return unless @addresses;
	$self->{rebuild_flag} = 1;
	
	my $list = $self->{contents};
	foreach my $add ( @addresses ) {
		# convert email to SHA1 hash if necessary
		$add = sha1_base64( $add ) if $add =~ /@/o;
		$list->{$add}++;
	}
	$self->{reindex_flag} = 1;
}

=item check ARGS

Checks the provided arg list against the bloom filter,
and returns a list of equivalent length, with true or
false values depending on whether there was a match.
Takes either email addresses or sha1_base64 hashes as args.

=cut 

sub check {	

	my ( $self, @keys ) = @_;

	$self->build_filter() if $self->{rebuild_flag} 
						  or !defined $self->{filter};
	
	return unless @keys;

	my $salt_count = scalar $self->{salts};

	my @result;

	# A match occurs if every bit we check is on
	foreach my $key ( @keys ) {
		my $mask = $self->_make_bitmask( $key );		
		push @result, ($mask == ( $mask & $self->{filter} ));
	}
	return ( wantarray() ? @result : $result[0] );
}

=item clear

Removes all addresses from the filter

=cut

sub clear {
	my ( $self ) = @_;
	$self->{contents} = {};
	$self->{salts} = [];
	$self->{rebuild_flag} = 1;
}



=item build_filter

Builds a bloom filter and stores it internally

=cut

sub build_filter {
	my ( $self ) = @_;

	croak "No salts have been set"
		unless exists $self->{available_salts}
		and ref $self->{available_salts}
		and ref $self->{available_salts} eq 'ARRAY';

	my ( $length ) = $self->_calculate_filter_length();

	# expand the filter length if necessary
	# but don't let the filter shrink below the
	# minimum allowed size

	if ( $length > $self->{min_length} ) {
		if ( $length > $self->{filter_length} ) {
			$self->{filter_length} = $length;
		}
	} else { 
		$self->{filter_length} = $self->{min_length};
	}

	my $bf = pack( "b*", '0' x $self->{filter_length} );

	# Hash our list of emails into the empty filter

	foreach my $key ( keys %{ $self->{contents}} ) {
		my $mask = $self->_make_bitmask( $key );
		$bf = $bf | $mask;
	}

	$self->{rebuild_flag} = 0;
	$self->{filter} = $bf;
}

=item on_bits

Returns the number of 'on' bits in the bloom filter

=cut

sub on_bits {
	my ( $self ) = @_;
	return unless $self->{filter};
	return unpack( "%32b*",  $self->{filter})
}



=item get_salts 

Returns the current list of salts

=cut

sub get_salts { 
	my ( $self ) = @_;
	return unless exists $self->{salts}
		and ref $self->{salts}
		and ref $self->{salts} eq 'ARRAY';

	return @{ $_[0]->{salts} };
}

=item set_salts ARRAY

Sets the salts to be used with this filter

=cut

sub set_salts {
	my ( $self, @salts ) = @_;
	$self->{available_salts} = \@salts;
	$self->{salts} = \@salts;
	$self->{reindex_flag} = 1;
	return scalar @salts;
}

=item set_error_rate RATE

Sets the maximum false positive rate on the filter to RATE.  RATE
must be a number between 0 and 1.

=cut

sub set_error_rate {
	my ( $self, $err_rate ) = @_;
	croak "Out of bounds value for error rate" unless
		$err_rate > 0 and
		$err_rate < 1;

	$self->{reindex_flag} = 1;
	$self->{error_rate} = $err_rate;

}

=back

=head1 INTERNAL METHODS

=over

=item _make_bitmask

Given a key, hash it using the list of salts and return a bitmask
the same length as the Bloom filter.  Note that Perl will pad the 
bitmask out with zeroes so it's a muliple of 8.

=cut

sub _make_bitmask {

	my ( $self, $key ) = @_;

	croak "Filter length is undefined" unless $self->{filter_length};
	my @salts = @{ $self->{salts} }
		or croak "No salts found, cannot make bitmask";

	my $mask = pack( "b*", '0' x $self->{filter_length});

	#print "\n====\n";
	foreach my $salt ( @salts ){ 

		my $hash = sha1( $key, $salt );

		# blank 32 bit vector
		my $vec = pack( "N", 0 ); 

		# split the 160-bit hash into five 32-bit ints
		# and XOR the pieces together

		my @pieces =  map { pack( "N", $_ ) } unpack("N*", $hash );
		$vec = $_ ^ $vec foreach @pieces;	

		# Calculate bit offset by modding

		my $result = unpack( "N", $vec );

		
		my $bit_offset = $result % $self->{filter_length};
		vec( $mask, $bit_offset, 1 ) = 1;	
		undef $result;
	}
	return $mask;
}

=item _calculate_filter_length

Using the stored information for number of salts, number of items, and
desired error rate, calculate how long to make the filter string to 
ensure the error rate stays within bounds.

=cut

sub _calculate_filter_length {

	my ( $self ) = @_;

	return unless $self->{contents};
	return unless $self->{available_salts};

	# forumla is 
	# m = -kn / ( ln( 1 - c ^ 1/k ) )

	my $salt_count  = scalar @{ $self->{available_salts} };
	my $c = $self->{error_rate} || croak "error rate not set";
	my $n = scalar keys %{ $self->{contents} };
	my $min_m = 10000000000;
	my $opt_k;
	foreach my $k ( 1.. $salt_count ){

		my $m = (-1 * $k * $n) / ( log( 1 - ($c ** (1/$k))));

		if ( !defined $min_m or ($m < $min_m) ){
			 $min_m = $m;
			 $opt_k = $k;
		}
	}
	my $m = int( $min_m) + 1;

	my @available = @{$self->{available_salts}};
	my @use_salts = splice( @available, 0, $opt_k );
	$self->{salts} = \@use_salts;
	return ( $m );
}

=back

=head1 AUTHOR

Maciej Ceglowski E<lt>maciej@ceglowski.comE<gt>

=head1 COPYRIGHT AND LICENSE

(c) 2004 Maciej Ceglowski, Joshua Schachter

This is free software, distributed under version 2
of the GNU Public License (GPL).  See L<LICENSE> for
full text.

=cut

1;

