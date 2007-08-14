package POE::Component::Server::NRPE::Constants;

use strict;

require Exporter;

our @ISA    = qw(Exporter);
our @EXPORT = qw(NRPE_STATE_OK NRPE_STATE_WARNING NRPE_STATE_CRITICAL NRPE_STATE_UNKNOWN);

use constant NRPE_STATE_OK 	 => 0;
use constant NRPE_STATE_WARNING  => 1;
use constant NRPE_STATE_CRITICAL => 2;
use constant NRPE_STATE_UNKNOWN  => 3;

1;

__END__

=head1 NAME

POE::Component::Server::NRPE::Constants - Defines constants required by POE::Component::Server::NRPE

=head1 SYNOPSIS

  use POE::Component::Server::NRPE::Constants;

=head1 DESCRIPTION

POE::Component::Server::NRPE::Constants defines constants required by L<POE::Component::Server::NRPE>.

=head1 AUTHOR

Chris Williams <chris@bingosnet.co.uk>

=head1 SEE ALSO

L<POE::Component::Server::NRPE>

L<http://nagiosplug.sourceforge.net/developer-guidelines.html>
