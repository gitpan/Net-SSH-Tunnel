package Net::SSH::Tunnel;

use 5.006;
use strict;
use warnings;
use Carp;
use Getopt::Long;
use Data::Dumper;
use Log::Log4perl qw(:easy);

=head1 NAME

Net::SSH::Tunnel - This is a simple wrapper around ssh to establish a tunnel.
Supports both local and remote port forwarding.

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';


=head1 SYNOPSIS

Perl module to setup / destroy a ssh tunnel.

    create a very short driver script.
    $ vi driver.pl
    #!/usr/bin/perl

    use strict;
    use warnings;
    use Net::SSH::Tunnel;
    
    Net::SSH::Tunnel->run();

    run the driver script with options.
    $ ./driver.pl --host dest.example.com --hostname hostname.example.com
    
    the above is equivalent to creating a local port forwarding like this:
    ssh -f -N -L 10000:dest.example.com:22 <effective username>@hostname.example.com

    after the driver script is done, you can then do:
    ssh -p 10000 user@localhost
    
    other usages:
    Usage: ./driver.pl --port 10000 --host dest.example.com --hostport 22 --hostname hostname.example.com
    Sets up a ssh tunnel.  Works on both local and remote forwarding.
    In the example above, it will create a tunnel from your host to
    hostname.example.com, where your local port 10000 is forwarded to
    dest.example.com's port 22.

    --hostname      specify the host where you create a tunnel from your host
    --host          specify the destination of port forwarding
    --user          user when connecting to <hostname>.  default: effective user
    --type          specify local or remote, for forwarding.  default: local
    --hostport      target port on <host>.  default: 22
    --port          source port for forwarding.  default: 10000
    --sshport       equivalent of -p <port> in ssh client.  default: 22
    --action        'setup' or 'destroy' a tunnel.  default: setup
    --help          prints the usage and exits
    --debug         turn on debug messages
    
    Notes on testing:
    This module wraps around ssh and as such, requires authentication.
    I have included test_deeply.pl that asks for hostnames, runs ssh and establishes a tunnel.
    If you'd like to test manually, please use the script.

=head1 SUBROUTINES/METHODS

=head2 new

    Description: The constructor.  Creates an object, invokes init() for argument parsing
    Arguments: none
    Returns: object

=cut

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    $self->init();
    return $self;
}

=head2 init

    Description: Arg parser.  Sets default values, uses Getopt::Long then do the necessary parsing.
    Arguments: none
    Returns: none, but updates the object with parsed args.  Croaks on error.
    
=cut

sub init {
    my $self = shift;

    $self->{ opts } = {
        hostport    => 22,
        port        => 10000,
        type        => 'local',
        action      => 'setup',
        help        => 0,
        debug       => 0,
        user        => scalar( getpwuid($>) ),
        sshport     => 22,
    };

    GetOptions(
        'hostname=s'    => \$self->{ opts }->{ hostname },
        'host=s'        => \$self->{ opts }->{ host },
        'type=s'        => \$self->{ opts }->{ type },
        'hostport=i'    => \$self->{ opts }->{ hostport },
        'port=i'        => \$self->{ opts }->{ port },
        'user=s'        => \$self->{ opts }->{ user },
        'sshport=i'     => \$self->{ opts }->{ sshport },
        'destroy'       => sub { $self->{ opts }->{ action } = 'destroy' },
        'help'          => \$self->{ opts }->{ help },
        'debug'         => sub { $self->{ opts }->{ debug }++ }, # for various debug levels, if needed
    );

    $self->usage() if ( !$self->{ opts }->{ hostname } || !$self->{ opts }->{ host } || $self->{ opts }->{ type } !~ /local|remote/ || $self->{ opts }->{ help } );
    Log::Log4perl->easy_init($DEBUG) if $self->{ opts }->{ debug };

    chomp( $self->{ cmds }->{ ssh } = `which ssh` );
    chomp( $self->{ cmds }->{ ps } = `which ps` );
    chomp( $self->{ cmds }->{ grep } = `which grep` );

    croak "ssh, ps or grep not found" unless( -x $self->{ cmds }->{ ssh } && -x $self->{ cmds }->{ ps } && -x $self->{ cmds }->{ grep } );
}

=head2 run

    Description: Driver method to do the new()->init() dance, then calls appropriate methods based on the args
    Arguments: none
    Returns: none, but may croak on error
    
=cut

sub run {
    my $class = shift;
    my $self = $class->new();
    
    my $action = $self->{ opts }->{ action };
    
    if ( $action eq 'setup' ) {
        DEBUG "Setting up tunnel";
        $self->setup_tunnel();
    }
    elsif( $action eq 'destroy' ) {
        DEBUG "Destroying tunnel";
        $self->destroy_tunnel();
    }
    return $self;
}

=head2 setup_tunnel

    Description: Establishes a ssh tunnel based on the object info.
    Arguments: none
    Returns: none, but may croak on error
    
=cut

sub setup_tunnel {
    my $self = shift;
    
    # this will seek for a tunnel according to params.  If found, just return
    return if ( $self->check_tunnel() );

    my $ssh         = $self->{ cmds }->{ ssh };
    my $hostport    = $self->{ opts }->{ hostport };
    my $port        = $self->{ opts }->{ port };
    my $hostname    = $self->{ opts }->{ hostname };
    my $host        = $self->{ opts }->{ host };
    my $user        = $self->{ opts }->{ user };
    my $type        = $self->{ opts }->{ type };
    my $sshport     = $self->{ opts }->{ sshport };
    
    my $command;
    if ( $type eq 'local' ) {
        $command = "$ssh -f -N -L $port:$host:$hostport -p $sshport $user\@$hostname";
    }
    elsif ( $type eq 'remote' ) {
        $command = "$ssh -f -N -R $port:$host:$hostport -p $sshport $user\@$hostname";
    }
    
    system( $command );
    my $ret = $? >> 8;
    croak "something went wrong while setting up a tunnel" if ( $ret );
}

=head2 check_tunnel

    Description: Runs ps and finds an existing tunnel, according to the parameters supplied
    Arguments: none
    Returns: pid of tunnel
    
=cut

sub check_tunnel {
    my $self = shift;

    # kind of redundant but I want to set shorter variables for readability
    my $ssh         = $self->{ cmds }->{ ssh };
    my $ps          = $self->{ cmds }->{ ps };
    my $grep        = $self->{ cmds }->{ grep };
    my $hostport    = $self->{ opts }->{ hostport };
    my $port        = $self->{ opts }->{ port };
    my $hostname    = $self->{ opts }->{ hostname };
    my $host        = $self->{ opts }->{ host };
    my $user        = $self->{ opts }->{ user };
    my $sshport     = $self->{ opts }->{ sshport };

    my $command = "$ps auxw | $grep $ssh | $grep $hostport | $grep $port | $grep $hostname | $grep $host | $grep $user | $grep $sshport | $grep -v grep";
    open( my $fh, "-|", $command ) or croak "could not execute $command: $!";
    
    my $pid;
    while( <$fh> ) {
        chomp;
        $pid = ( split( /\s+/, $_ ) )[1];
    }
    ( $pid ) ? $pid : undef;
}

=head2 destroy_tunnel

    Description: Calls check_tunnel() for existing tunnel, and if it exists, kills it.
    Arguments: none
    Returns: none, croaks if it fails to kill.  if there wasn't a tunnel, it doesn't do anything
    
=cut

sub destroy_tunnel {
    my $self = shift;
    
    my $pid = $self->check_tunnel();
    if ( $pid ) {
        my $rc = kill 15, $pid;
        croak "could not kill tunnel" unless( $rc );
    }
}

=head2 usage

    Description: The sub to provide help.
    Arguments: none
    Returns: none, and exits
    
=cut

sub usage {
    my $self = shift;

    print <<USAGE;
Usage: ./driver.pl --port 10000 --host dest.example.com --hostport 22 --hostname hostname.example.com
    Sets up a ssh tunnel.  Works on both local and remote forwarding.
    In the example above, it will create a tunnel from your host to
    hostname.example.com, where your local port 10000 is forwarded to
    dest.example.com's port 22.

    --hostname      specify the host where you create a tunnel from your host
    --host          specify the destination of port forwarding
    --user          user when connecting to <hostname>.  default: effective user
    --type          specify local or remote, for forwarding.  default: local
    --hostport      target port on <host>.  default: 22
    --port          source port for forwarding.  default: 10000
    --sshport       equivalent of -p <port> in ssh client.  default: 22
    --action        'setup' or 'destroy' a tunnel.  default: setup
    --help          prints the usage and exits
    --debug         turn on debug messages
USAGE
    exit(0);
}

=head1 AUTHOR

Satoshi Yagi, C<< <satoshi.yagi at yahoo.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-ssh-tunnel at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-SSH-Tunnel>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::SSH::Tunnel


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-SSH-Tunnel>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-SSH-Tunnel>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-SSH-Tunnel>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-SSH-Tunnel/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Satoshi Yagi.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::SSH::Tunnel
