package POE::Component::Server::NRPE::SSLify;

use strict qw(subs vars refs);
our $VERSION = '0.02';

# We need Net::SSLeay or all's a failure!
BEGIN {
	eval { require Net::SSLeay };

	# Check for errors...
	if ( $@ ) {
		# Oh boy!
		die $@;
	} 
	else {
		# Finally, load our subclass :)
		require POE::Component::Server::NRPE::SSLify::ServerHandle;

		# Initialize Net::SSLeay
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		Net::SSLeay::randomize();
	}
}

# Do the exporting magic...
require Exporter;
use vars qw( @ISA @EXPORT_OK );
@ISA = qw( Exporter );
@EXPORT_OK = qw( Server_SSLify SSLify_Initialise );

# Bring in some socket-related stuff
use Symbol qw( gensym );
use POSIX qw( F_GETFL F_SETFL O_NONBLOCK EAGAIN EWOULDBLOCK );

# We need the server-side stuff
use Net::SSLeay qw( die_now die_if_ssl_error );

# The server-side CTX stuff
my $ctx = undef;

# Helper sub to set blocking on a handle
sub Set_Blocking {
	my $socket = shift;

	# Net::SSLeay needs blocking for setup.
	#
	# ActiveState Perl 5.8.0 dislikes the Win32-specific code to make
	# a socket blocking, so we use IO::Handle's blocking(1) method.
	# Perl 5.005_03 doesn't like blocking(), so we only use it in
	# 5.8.0 and beyond.
	if ( $] >= 5.008 and $^O eq 'MSWin32' ) {
		# From IO::Handle POD
		# If an error occurs blocking will return undef and $! will be set.
		if ( ! $socket->blocking( 1 ) ) {
			die "Unable to set blocking mode on socket: $!";
		}
	} else {
		# Make the handle blocking, the POSIX way.
		if ( $^O ne 'MSWin32' ) {
			# Get the old flags
			my $flags = fcntl( $socket, F_GETFL, 0 ) or die "fcntl( $socket, F_GETFL, 0 ) fails: $!";

			# Okay, we patiently wait until the socket turns blocking mode
			until( fcntl( $socket, F_SETFL, $flags & ~O_NONBLOCK ) ) {
				# What was the error?
				if ( ! ( $! == EAGAIN or $! == EWOULDBLOCK ) ) {
					# Fatal error...
					die "fcntl( $socket, FSETFL, etc ) fails: $!";
				}
			}
		} else {
			# Darned MSWin32 way...
			# Do some ioctl magic here
			# 126 is FIONBIO ( some docs say 0x7F << 16 )
			my $flag = "0";
			ioctl( $socket, 0x80000000 | ( 4 << 16 ) | ( ord( 'f' ) << 8 ) | 126, $flag ) or die "ioctl( $socket, FIONBIO, $flag ) fails: $!";
		}
	}

	# All done!
	return $socket;
}

sub Server_SSLify {
	# Get the socket!
	my $socket = shift;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# If we don't have a ctx ready, we can't do anything...
	if ( ! defined $ctx ) {
		die 'Please do SSLify_Initialise() first';
	}

	# Set blocking on
	$socket = Set_Blocking( $socket );

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::Server::NRPE::SSLify::ServerHandle', $socket, $ctx ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

sub SSLify_Initialise {
	my $data = "-----BEGIN DH PARAMETERS-----\nMEYCQQD9eJtH5rywhI/PGD+RaFvEptXwGrqtjm4Jw+GSniG72OLThcOcb29iEIcp\nXgrpPtClVGHYs4lNZbpwFz1ufNnjAgEC\n-----END DH PARAMETERS-----\n";
	$ctx = Net::SSLeay::CTX_tlsv1_new() or die_now( "Failed to create SSL_CTX $!" );
        Net::SSLeay::CTX_set_cipher_list( $ctx, "ADH") or die_now( " Failed to set cipher list $!" );
        my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem() ) or die_now( "Failed to create BIO: $!" );
        my $retval = Net::SSLeay::BIO_write( $bio, $data );
        my $dh = Net::SSLeay::PEM_read_bio_DHparams( $bio ) or die_now( "Failed to read DHparams: $!" );
        Net::SSLeay::BIO_free( $bio );
        Net::SSLeay::CTX_set_tmp_dh( $ctx, $dh ) or die_now( "Failed to set tmp DH: $!" );
        Net::SSLeay::DH_free( $dh );
	return 1;
}

1;
__END__

=head1 NAME

POE::Component::Server::NRPE::SSLify - Makes using NRPE SSL in the world of POE easy!

=head1 SYNOPSIS

	# Import the module
	use POE::Component::Server::NRPE::SSLify qw( Server_SSLify SSLify_Initialise);

	eval { SSLify_Initialise(); };
	if ( $@ ) {
		# Unable to initialise the SSL CTX
	}

	# Create a normal SocketFactory wheel or something
	my $factory = POE::Wheel::SocketFactory->new( ... );

	# Converts the socket into a SSL socket POE can communicate with
	eval { $socket = Server_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		...
	);

	# Use it as you wish...

=head1 ABSTRACT

	Makes NRPE SSL use in POE a breeze!

=head1 DESCRIPTION

This is a hack of L<POE::Component::SSLify> to support NRPE's SSL negotitation which uses TLSv1 and DH ciphers.

=head1 FUNCTIONS

=head2 SSLify_Initialise

	Initialises the server-side CTX by loading the NRPE Diffie-Hellman Parameters.

=head2 Server_SSLify

	Accepts a socket, returns a brand new socket SSLified

	NOTE: SSLify_Initialise must be set first!

=head1 BUGS

On Win32 platforms SSL support is pretty shaky, please help me out with detailed error descriptions if it happens to you!

=head1 SEE ALSO

L<POE>

L<POE::Component::SSLify>

L<Net::SSLeay>

=head1 AUTHOR

Apocalypse E<lt>apocal@cpan.orgE<gt>

=head1 PROPS

	Original code is entirely Rocco Caputo ( Creator of POE ) -> I simply
	packaged up the code into something everyone could use and accepted the burden
	of maintaining it :)

	From the PoCo::Client::HTTP code =]
	# TODO - This code should probably become a POE::Kernel method,
    	# seeing as it's rather baroque and potentially useful in a number
    	# of places.

	Big thanks to Florian Ragwitz for his help and advice the minefield that is
	OpenSSL.

=head1 COPYRIGHT AND LICENSE

Copyright 2007 by Apocalypse/Rocco Caputo

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
