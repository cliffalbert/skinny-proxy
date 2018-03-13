#!/usr/bin/perl -w
BEGIN {
($version) = '$Id: skinny-proxy.pl,v 1.48 2003/05/19 00:03:05 tuxje Exp $'
  =~ /v (\S+)/;

$debugMode = 1;

$text_refresh = 1800;  # Refresh-interval in whole seconds
$text_speed   = .15;   # Scroll-interval in seconds
$text_speed2  = undef; # Do not touch

# Comment the next line to enable the text scrolling on startup:
($text_speed2, $text_speed) = ($text_speed, $text_speed2);

$usage = qq{
    Usage: $0 local_ip public_ip callmanager_ip
    Example: $0 192.168.1.1 24.24.24.24 25.25.25.25

    local_ip       Should correspond to a local TCP/IP interface
    public_ip      Should be an IP address that is reachable from the internet
    callmanager_ip The IP address of the CallManager, see
                   http://ipphone.patser.net/ (in Dutch)
};

$credits = q{
    Based on port-forward[1] by Tkil (1999).
    Active developers:
    - Cliff Albert
    - Gerard Oskamp
    - Jorrit Waalboer
    
    [1] http://slinky.scrye.com/~tkil/perl/port-forward
};

$copyright = q{
    (c) 1999 Tkil
    (c) 2002 %%
    This proxy is free software; you can redistribute it and/or modify it under
    the same terms as Perl.
};

$copyright =~ s[%%]{ join ', ', $credits =~ /^\s*- (.*)/gm }e;

if (@ARGV != 3) {
    print join '', "\nskinny-proxy v$version, proxy\@ipphones.nl\n", $usage,
      $copyright, "\n";
    exit;
}

}; # /begin

#Proxy commands:
# Dial "##1#33#", "##1#34#" ... "##1#37#" to test dial tones
# Dial "##2##" to enable/disable the text scrolling feature
# Dial "##3##" to reset the proxy, removing all sockets, killing all UDP fwds
# Dial "##4#3#" to test the ringer, "##4#1#" to stop the ringer
# Dial "##11##" to put the phone off-hook, sleepy-sleep mode
# Dial "##12##" to put it on-hook again

use strict;
use Carp qw(croak cluck);
use IO::Socket;
use IO::Select;
use POSIX;
use Socket qw(INADDR_ANY PF_INET SOCK_DGRAM sockaddr_in inet_ntoa inet_aton);
use Sys::Hostname;

use vars qw(
    %messages %rmessages
    $version $usage $credits $copyright
    $debugMode
    $text_speed $text_speed2 $text_refresh
);

$| = 1;

my ($expect_ack, $select, $proxy_host, $server_host, $local_host, @reaped);

use constant IO_BUF_SIZE => 1024;     # how much data should we snarf at once?
use constant LISTEN_MAX  => 10;       # max clients

my $proxy_port  = 2000;
my @local_ports = 4666 .. 4676;
my $server_port = 2000;
my (%used_ports, %calls);

# now some hashes to map client connections to server connections.
my (%client_of_server, %server_of_client);

# and one more hash, from socket name to real socket:
my %socket_of;

my ($text, $text_offset, $text_settime, $do_text);

# First sub
sub debug {
    return unless $debugMode;
    if (ref $_[0] eq 'HASH') {
	my %hash = %{ $_[0] };
	for (values %hash) {
	    if (defined) {
		s/([\0\cA-\cZ])/"\e[7m" . chr(64 + ord $1) . "\e[0m"/eg;
		s/ /\e[30;1m*\e[0m/g;
	    } else {
		$_ = "\e[30;1mundef\e[0m";
	    }
	}
	print map "  $_: $hash{$_}\n", grep !/^_/, keys %hash;
	return;
    }
    print STDERR map "$_\n", @_;
}

$SIG{CHLD} = sub {
    debug 'SIGCHLD';
    push @reaped, wait;
    debug { ReapedPID => $reaped[-1] };
};

sub http_get {
    my($host, $port, $path) = @_;
    my $sock = IO::Socket::INET->new(
	    PeerAddr => $host,
	    PeerPort => $port,
	    Proto    => 'tcp',
	    Timeout  => 60
    ) or return undef;
    $sock->autoflush;
    my $netloc = $host;
    $netloc .= ":$port" if $port != 80;
    print $sock join("\015\012" => "GET $path HTTP/1.0", "Host: $netloc",
      "User-Agent: $0/$version", '', '');

    my $buf = '';
    my $n;
    1 while $n = sysread($sock, $buf, 8192, length($buf));
    return undef unless defined($n);
    $buf =~ s/.+?\015?\012\015?\012//s;
    return $buf;
}

sub set_text {
    my $c = http_get 'www.knmi.nl', 80, '/voorl/weer/verwachting.html';
    if (
	defined $c
	and my ($datum, $tijd) = 
	$c =~ /Opgesteld\s+door\s+het\s+KNMI\s+
	       op\s+(.*\d),\s+om\s+(\d+:\d+)\s+uur\./x
    ) {
	$datum =~ s/\s+/ /g;
	my $weer = join ' Wind: ', $c =~ m[<pre\s*>([^<]*)</pre>]sg;
	$weer =~ s/\s+/ /g;
	$text = "$weer (KNMI $datum $tijd)";
    } else {
	$text = "Dan volgt nu de weersverwachting. Er worden middagtemperaturen
	verwacht van 1 uur 's middags tot zes uur 's avonds. Er waait een zachte
	zuidoostelijke wind en met 22 graden wordt het een aangename dag. Met 36
	graden wordt het een hete dag. Met 2 graden wordt het een frisse dag.
	Verder verwacht het KNMI gladheid in het hele land met uitzondering van
	de antillen. -- Herman Finkers";
	$text =~ s/\s+/ /g;
    }
    $text = (' ' x 20) . $text . (' ' x 19);
    $text_offset = 0;
    $text_settime = time;
}

sub update_text {
    set_text() unless defined $text and length $text;
    set_text() if time() - $text_settime > $text_refresh;
    $text_offset = 0 if $text_offset > -20 + length $text;
    my $up = substr $text, $text_offset++, 20;
    my $packet = assemble(
	'DisplayText',
	Text => $up . strftime('%d/%m/%y     ', localtime)
    );
    syswrite $_, $packet for values %client_of_server;
}

sub udp_forward {
    my ($local_rtp, $remote_rtp) = @_;

    die "Bad listen address\n" if $local_rtp !~ /([^:]+):(\d+)/;
    my $server_saddr = sockaddr_in($2, INADDR_ANY); 

    die "Bad forward address\n" if $remote_rtp !~ /([^:]+):(\d+)/;
    my $forward_saddr = sockaddr_in($2, inet_aton($1));
    my $forward_addr  = "$1:$2";

    socket(SERVSOCK, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
      or die "socket: $!";
    bind(SERVSOCK, $server_saddr) or die "Could not bind ($!)";

    # scan all the servers
    print "Forwarding started\n";

    while (1) {
        my $rin = '';
        vec($rin, fileno(SERVSOCK), 1) = 1;

        select(my $rout = $rin, undef, undef, undef) or next;
	
	my $paddr = recv SERVSOCK, my $buf, 2048, 0
	  or die "Could not recv ($!)";

	my ($fromport, $addr) = sockaddr_in($paddr);
	my $fromaddr = inet_ntoa($addr);

	my $send_saddr = $forward_addr eq "$fromaddr:$fromport"
	  ? $server_saddr
	  : $forward_saddr;

	defined send(SERVSOCK, $buf, 0, $send_saddr)
	  or die "Could not send ($!)";
    }

}

sub dectodot { inet_ntoa pack 'V', shift }

sub add_client_sock {
    my ($client) = @_;

    debug 'Accepted phone connection';
    debug {
	PhoneHost => $client->peerhost,
	PhonePort => $client->peerport, 
	LocalPort => $client->sockport
    };

    # open the proxied connection...
    my $server = IO::Socket::INET->new(
        PeerAddr => $server_host,
        PeerPort => $server_port,
        Proto    => 'tcp'
    ) or do {
	warn "Could not connect to CM at $server_host:$server_port ($!)\n";
	return;
    };

    debug 'Connected to CallManager';
    debug {
	CMHost    => $server->peerhost,
	CMPort    => $server->peerport,
	LocalPort => $server->sockport
    };

    # now populate the hashes.
    $socket_of{$client}        = $client;
    $socket_of{$server}        = $server;
    $client_of_server{$server} = $client;
    $server_of_client{$client} = $server;

    # and add both socket to the IO::Select object
    $select->add($client);
    $select->add($server);
}

sub remove_socket {
    my ($sock) = @_;

    # determine the "other half" of this socket, removing it from the
    # hash as we go.
    my ($dest_sock, $source, $other);
    if (exists $client_of_server{$sock}) {
        $dest_sock = delete $client_of_server{$sock};
        delete $server_of_client{$dest_sock};
	$source = 'CallManager';
	$other = 'phone'
    } elsif (exists $server_of_client{$sock}) {
        $dest_sock = delete $server_of_client{$sock};
        delete $client_of_server{$dest_sock};
	$source = 'phone';
	$other = 'CallManager';
    } else {
        cluck 'Could not find socket';
    }

    debug "Closing $source connection";
    debug {
	PhoneHost => $sock->peerhost,
	PhonePort => $sock->peerport, 
	LocalPort => $sock->sockport
    };
    debug "Closing $other connection";
    debug {
	PhoneHost => $dest_sock->peerhost,
	PhonePort => $dest_sock->peerport, 
	LocalPort => $dest_sock->sockport
    };

    # remove them from the rest of the hashes, as well.
    delete $socket_of{$sock};
    delete $socket_of{$dest_sock};

    # and from the IO::Select object
    $select->remove($sock);
    $select->remove($dest_sock);

    # and close them.
    $sock->close;
    $dest_sock->close;
}

sub assemble {
    my $message = shift;
    #   $message, %arghash  if arguments known in %messages
    #   $message, $argarray if arguments unknown in %messages
    #             ^ assumes all V-templates
    my ($id) = grep { $messages{$_}[0] eq $message } keys %messages;
    croak "Unknown message '$message'" if not defined $id;
    my @args = @{ $messages{$id} };
    shift @args;
    my $res = '';
    if (@args == 0 and ref $_[0] eq 'ARRAY') {
	$res = pack 'V*', @{ $_[0] };
    } else {
	my %args = @_;
	for (@args) {
	    my ($template, $name) = split /_/, $_, 2;
	    croak "Missing argument '$name'" if not defined $args{$name};
	    if ($template eq '*') {
		$args{$name} = unpack 'V', inet_aton $args{$name};
		$template = 'V';
	    }
	    $res .= pack $template, $args{$name};
	    delete $args{$name};
	}
	croak "Unknown argument(s) '@{[ keys %args ]}'" if keys %args;
    }
    
    return pack 'V V2 a*', 4 + length $res, 0, $id, $res;
}    

my $keys;
    
sub process_data {
    my ($sock) = @_;

    # determine the "other half" of this socket.
    my ($dest_sock, $source);
    if (exists $client_of_server{$sock}) {
        $dest_sock = $client_of_server{$sock};
        $source    = 'CallManager';
    } elsif (exists $server_of_client{$sock}) {
        $dest_sock = $server_of_client{$sock};
        $source    = 'Phone';
    } else {
        cluck 'Could not find socket';
        return;
    }

    # read the actual data.  punt if we error.
    my $buffer = '';
    my $n_read = sysread($sock, $buffer, IO_BUF_SIZE) or do {
        remove_socket($sock);
        return;
    };

    # Packets zijn kuddedieren...
    my @packets;
    while (length $buffer) {
	push @packets, { };
	my ($length) = unpack 'V a*', $buffer;
	my $data = substr $buffer, 0, $length + 8, '';
	@{ $packets[-1] }{qw/_data length reserved message_id content/} =
	  ($data, unpack 'V V2 a*', $data);
    }

    # Don't just stand there; do something! :)
    for my $packet (@packets) {
	my $message_id = $packet->{message_id};
	if (not length $message_id) {
	    debug 'Strange packet';
	    next;
	}
	my $hexid = sprintf "0x%x", $message_id;
	
	my $args = exists $messages{$message_id}
	  ? [ @{ $messages{$message_id} } ]
	  : [ "UndocumentedMessage $hexid" ];
	
	my $message = shift @$args;
	
	debug "$source: $message";

	my %data;
	if (@$args) {
	    my $template = '';
	    my @names;
	    my @ip;
	    for (@$args) {
		die "Malformed attr ($_)" if not /([^_]+)_(.*)/;
		if ($1 eq '*') { # IP
		    $template .= 'V';
		    push @ip, $2;
		} else {
		    $template .= $1;
		}
		push @names, $2;
	    }
	    @data{@names} = unpack $template, $packet->{content};
	    $_ = dectodot $_ for @data{@ip};
	}

	# Stuff that modifies %data
	if ($message eq 'DefineTimedate') {;
            my @data = unpack('V9', $packet->{content});
	    $data[1] -= 1;
	    if ($data[0] > 1900) {
		$data[0] -= 1900;
	    } elsif ($data[0] < 70) {
		$data[0] += 100
	    }
	    @data{qw/Date _content/} = (
		strftime(
		    "%d/%m/%y %H:%M:%S",
		    @data[6, 5, 4, 3, 1, 0, 2], 0, 0
		),
		$data[-1]
	    );

	    $do_text = 1;
        } elsif ($message =~ /^UndocumentedMessage/) {
	    $data{Content} = $packet->{content};
	}

	debug \%data if keys %data;

	# Stuff that actually *does* something with it
	if ($message eq 'CloseReceiveChannel') {
            my $pid = $calls{ $data{PassThruPartyID} };

	    if(defined $pid) {
                print
	          "Terminating UDP forward for call $data{PassThruPartyID}, pid " .
	          "$pid with port $used_ports{$pid}"
		    unless $debugMode;
        
	        debug 'Killing UDP forwarder';
	        debug { PID => $pid, Call => $data{PassThruPartyID} };
                kill 15, $pid;
	    } else {
                print
	          "I want to terminate the UDP forward for call $data{PassThruPartyID}, " .
		  "but I have no pid?!"
		    unless $debugMode;
	    }

	    $do_text = 1;
        } elsif ($message eq 'StationRegisterReject') {
	    $packet->{_data} = assemble('DisplayText', Text => $data{Display});
	    $do_text = 0;
	} elsif ($message eq 'DefineTimedate') {
	    # We synchronize time to the local machine time
	    # This will accomodate local time zone settings
	    my @localtime = localtime();
	    $localtime[4] += 1;
	    $packet->{_data} = assemble(
		'DefineTimedate',
		[ @localtime[5, 4, 6, 3, 2, 1, 0], 0, 0 ]
	    );
        } elsif ($message eq 'CallInfo') {
            print "Incoming call from $data{CallingPartyName} (" .
	      "$data{CallingParty}) for $data{CalledPartyName} (" .
	      "$data{CalledParty})\n"
              unless $debugMode;
	      $do_text = 0;
        } elsif ($message eq 'StartMediaTransmission') {
            print "Call established with "
              . "$data{RemoteIPAddr}:$data{RemotePortNumber}\n";
        } elsif ($message eq 'OpenReceiveChannelAck') {
            my $local_port = pop @local_ports;
            debug "Assigned port $local_port";

	    $packet->{_data} = assemble(
		'OpenReceiveChannelAck',
		ORCStatus       => $data{ORCStatus},
		ipAddress       => $local_host,
		PortNumber      => $local_port,
		PassThruPartyID => $data{PassThruPartyID}
	    );
	    
            my $remote_rtp = "$data{ipAddress}:$data{PortNumber}";
            my $local_rtp = "$local_host:$local_port";

            if (my $pid = fork) {
		debug 'Starting UDP forwarding';
                
		debug {
		    ChildPID => $pid,
		    Port => $local_port,
		    Call => $data{PassThruPartyID}
		};

                $used_ports{$pid} = $local_port;
                $calls{ $data{PassThruPartyID} } = $pid;

                print "Created UDP forward for call $data{PassThruPartyID}, "
		  . "pid $pid with port $local_port\n"
                  unless $debugMode;
            } elsif (defined $pid) {
                udp_forward($local_rtp,$remote_rtp);
            } else {
		die "Could not fork ($!)";
	    }
	} elsif ($message eq 'ClearDisplay') {
	    $do_text = 1;
        } elsif ($message eq 'DisplayText') {
	    if ($data{Text} !~ /\S/) {
		$do_text = 1;
		# ClearDisplay also removes the three chars in front of
		# the time.
		$packet->{_data} = assemble('ClearDisplay');
	    } else {
		$do_text = 0;
	    }
	} elsif ($message eq 'KeypadButton') {
	    $keys .= sprintf '%X', $data{Button};
	    $keys =~ tr/EF/*#/;
	    if ($keys =~ /^##/) {
		$do_text = 0;
		if ($keys =~ /^##$/) {
		    syswrite $sock, assemble('StopTone');
		    syswrite $sock, assemble('ClearDisplay');
		    debug 'Phone entering proxy command mode.';
		}
		syswrite $sock, assemble('DisplayText', Text => $keys);
		if ($keys =~ /^##(\d+)#(\d*)#/) {
		    debug "Proxy command";
		    debug { Command => $1, Parameter => $2 };
		    if ($1 == 1) {
			syswrite $sock, assemble('StartTone', DeviceTone => $2);
		    } elsif ($1 == 2) {
			($text_speed, $text_speed2) =
			($text_speed2, $text_speed);
		    } elsif ($1 == 3) {
			# Not %socket_of, it'd close everything twice
			remove_socket $_ for values %client_of_server;
			kill 15, $_ for values %calls;
			%calls = ();
			$keys = '';
			return;
		    } elsif ($1 == 4) {
			syswrite $sock, assemble('SetRinger', Ringer => $2);
		    } elsif ($1 == 11) {
		  	# Go silently offhook
		        syswrite $dest_sock, assemble('OffHook');
		    } elsif ($1 == 12) {
			# Go silently onhook
			syswrite $dest_sock, assemble('OnHook');
		    }
		    $keys = '';
		    syswrite $sock, assemble('ClearDisplay');
		    $do_text = 1;
		}
		return; # Avoid sending it to the CM
	    } elsif ($do_text and $keys ne '#') {
		# I assume on-hook when $do_text is true
		$keys = '';
	    }
	} elsif ($message eq 'KeepAlive') {
    	    ## We are receiving an KeepAlive and are waiting on an Ack
	    ## This is bad so we reconnect 
            if (defined($expect_ack)) {
	 	$expect_ack = undef;
                debug "Possible link loss";
                remove_socket $_ for values %client_of_server;
                kill 15, $_ for values %calls;
                %calls = ();
                $keys = '';
		return;
            } else {   
	        $expect_ack = time;
	    }
	} elsif ($message eq 'KeepAliveAck') {
	    if (defined($expect_ack)) {
 	       $expect_ack = undef;
	    } else {
	       debug 'Received an KeepAliveAck without a KeepAlive';
	    }
	} elsif ($message =~ /Hook$/) {
	    $keys = '';
	}
	syswrite $dest_sock, $packet->{_data};
    }
}

print 
qq{Warning: This program is considered to be beta quality. It may or may not
work as expected. Use at your own risk.

skinny-proxy v$version, proxy\@ipphones.nl

};

($proxy_host, $local_host, $server_host) = @ARGV;
$proxy_port  = $1 if $proxy_host  =~ s/:(\d+)$//;
$server_port = $1 if $server_host =~ s/:(\d+)$//;

if ($local_host =~ s/:([\d-]+)//) {
    if ($1 =~ /(\d+)-(\d+)/) {
        print "Forwarding from $local_host:$1-$2\n";
        @local_ports = $1 .. $2;
    } else {
        @local_ports = $1;
        print "Forwarding from $local_host:$1\n";
    }
}

print "Setting up listening socket on $proxy_host:$proxy_port\n";

# setup listening port
my $listen_sock = IO::Socket::INET->new(
    LocalAddr => $proxy_host,
    LocalPort => $proxy_port,
    Proto     => 'tcp',
    Type      => SOCK_STREAM,
    Listen    => LISTEN_MAX,
    Reuse     => 1
) or die "Could not bind listening socket $proxy_host:$proxy_port ($!)";

# create the IO::Select that will control our universe.  add the
# listening socket.
$select = IO::Select->new($listen_sock);

while (1) {
    my @handles = IO::Select::select($select, undef, $select, $text_speed);
    if (@handles == 0) {
	update_text() if $do_text;
	next;
    }
    # remove any sockets that are in error
    my %removed;
    for (@{ $handles[2] }) {
        remove_socket($_);
        $removed{$_} = 1;
    }

    # get input from each active socket
    for my $sock (grep { not exists $removed{$_} } @{ $handles[0] }) {
        # any new sockets?
        if ($sock == $listen_sock) {
            my $new_sock = $listen_sock->accept or do {
		warn "Could not accept ($!)";
		next;
	    };
            add_client_sock($new_sock);
        } else {
            # just move along.
            process_data($sock);
        }
    }

    while (my $pid = pop @reaped) {
	my ($id) = grep { $calls{$_} == $pid } keys %calls;
	
	debug "Cleaning up after call $id.";
	debug { PID => $pid, Port => $used_ports{$pid} };
	
	push @local_ports, $used_ports{$pid};

	delete $calls{$id};
	delete $used_ports{$pid};
    }
}

BEGIN {
%messages = (
0x200 => [ Oops                     => qw( ) ],
0x11b => [ RegisterTokenReject      => qw( V_WaitTime ) ],
0x11a => [ RegisterTokenAck         => qw( ) ],
0x119 => [ BackSpaceReq             => qw( V_LineInstance V_CallIdentifier ) ],
0x118 => [ UnregisterAck            => qw( V_Status ) ],
0x117 => [ DeactivateCallPlane      => qw( ) ],
0x116 => [ ActivateCallPlane        => qw( V_LineInstance) ],
0x115 => [ ClearNotify              => qw( ) ],
0x114 => [ DisplayNotify            => qw( V_TimeOut Z32_DisplayMessage ) ],
0x113 => [ ClearPrompt              => qw( V_LineInstance V_CallIdentifier ) ],
0x112 => [ DisplayPromptStatus      => qw( V_TimeOut Z32_DisplayMessage
                                           V_LineInstance V_CallIdentifier ) ],
0x111 => [ CallState                => qw( V_CallState
                                           V_LineInstance V_CallIdentifier) ],
0x110 => [ SelectSoftKeys           => qw( ) ],
0x109 => [ SoftKeySetRes            => qw( ) ],
0x108 => [ SoftKeyTemplateRes       => qw( ) ],
0x107 => [ ConnectionStatisticsReq  => qw( Z24_DirNumber V_CallIdentifier
                                           V_StatsProcessingType ) ],
0x106 => [ CloseReceiveChannel      => qw( V_ConferenceID V_PassThruPartyID ) ],
0x105 => [ OpenReceiveChannel       => qw( V_ConferenceID V_PassThruPartyID
                                           V_msPacketSize V_PayLoadCapability
					   V_EchoCancelType V_G723BitRate ) ],
0x104 => [ StopMulticastMediaTransmission
                                    => qw( V_ConferenceID V_PassThruPartyID ) ],
0x103 => [ StopMulticastMediaReception
                                    => qw( V_ConferenceID V_PassThruPartyID ) ],
0x102 => [ StartMulticastMediaTransmission
                                    => qw( V_ConferenceID V_PassThruPartyID
				           V_MulticastIPAdress V_MulticastPort
					   V_msPacketSize V_PayloadCapability
					   V_Precedence V_SilenceSuppression
					   v_MaxFramesPerPacket V_G723BitGate
					   ) ],
0x101 => [ StartWulticastMediaRecepion
                                    => qw( V_ConferenceID V_PassThruPartyID
				           V_MulticastIPAdress V_MulticastPort
					   V_msPacketSize V_PayloadCapability
					   V_EchoCancelType V_G723BitRate ) ],
0x100 => [ KeepAliveAck             => qw( ) ],
0x9f  => [ Reset                    => qw( V_DeviceResetType ) ],
0x9e  => [ ServerRes                => qw( ) ],
0x9d  => [ StationRegisterReject    => qw( Z33_Display ) ],
0x9c  => [ EnunciatorCommand        => qw( ) ],
0x9b  => [ CapabilitiesReq          => qw( ) ],
0x9a  => [ ClearDisplay             => qw( ) ],
0x99  => [ DisplayText              => qw( Z33_Text ) ],
0x98  => [ Version                  => qw( Z16_Version ) ],
0x97  => [ ButtonTemplate           => qw( ) ],
0x96  => [ StopSessionTransmission  => qw( *_RemoteIPAddr V_SessionType ) ],
0x95  => [ StartSessionTransmission => qw( *_RemoteIPAddr V_SessionType ) ],
0x94  => [ DefineTimedate           => qw( ) ], #
0x93  => [ ConfigStat               => qw( Z16_DeviceName V_StationUserID
                                           V_StationUserInstance
					   Z16_UserName Z16_ServerName
					   V_NumberLines V_NumberSpeedDials ) ],
0x92  => [ LineStat                 => qw( V_LineNumber Z24_LineDirNumber
                                           Z40_LineDisplayName ) ],
0x91  => [ SpeedDialStat            => qw( V_SpeedDialNumber
                                           Z24_SpeedDialDirNumber
					   Z40_SpeedDialDisplayName ) ],
0x90  => [ ForwardStat              => qw( V_ActiveForward V_LineNumber
                                           V_ForwardAllActive
					   Z24_ForwardAllNumber
					   V_ForwardBusyActive
					   Z24_ForwardBusyNumber
					   V_ForwardNoAnswerAnswerActive
					   Z24_ForwardNoAnswerNumber ) ],
0x8f  => [ CallInfo                 => qw( Z40_CallingPartyName Z24_CallingParty
                                           Z40_CalledPartyName Z24_CalledParty
                                           V_LineInstance V_CallIdentifier
					   V_CallType
					   Z40_originalCalledPartyName
					   Z24_originalCalledParty ) ],
0x8d  => [ StopMediaReception       => qw( ) ],
0x8c  => [ StartMediaReception      => qw( ) ],
0x8b  => [ StopMediaTransmission    => qw( V_ConferenceID V_PassThruPartyID ) ],
0x8a  => [ StartMediaTransmission   => qw( V_ConferenceID V_PassThruPartyID
                                           *_RemoteIPAddr V_RemotePortNumber
                                           V_MilliSecondPacketSize
					   V_PayLoadCapability V_PrecedenceValue
		                           V_SilenceSuppresion
					   v_MaxFramesPerPacket V_G723BitRate )
                                       ],
0x89  => [ SetMicroMode             => qw( ) ],
0x88  => [ SetSpeakerMode           => qw( ) ],
0x87  => [ SetHkFDetect             => qw( ) ],
0x86  => [ SetLamp                  => qw( V_Stimulus V_StimulusInstance
                                           V_LampMode ) ],
0x85  => [ SetRinger                => qw( V_Ringer ) ],
0x83  => [ StopTone                 => qw( ) ],
0x82  => [ StartTone                => qw( V_DeviceTone ) ],
0x81  => [ RegisterAck              => qw( V_KeepAliveInterval Z6_DateTemplate
                                           V_SecondaryKeepAliveInterval ) ],
0x29  => [ RegisterTokenReq         => qw( Z16_DeviceName V_StationUserID
                                           V_StationInstance V_IPAddress
					   V_DeviceType ) ],
0x28  => [ SoftKeyTemplateReq       => qw( ) ],
0x27  => [ Unregister               => qw( ) ],
0x26  => [ SoftKeyEvent             => qw( V_SoftKeyEvent V_LineInstance
                                           V_CallIdentifier ) ],
0x25  => [ SoftKeySetReq            => qw( ) ],
0x24  => [ OffHookWithCgpn          => qw( Z24_CalledParty ) ],
0x23  => [ ConnectionStatisticsRes  => qw( Z24_DirectoryNumber V_CallIdentifier
                                           V_StatsProcessingType V_PacketsSent
					   V_OctetsSent V_PacketsRecv
					   V_OctetsRecv V_PacketsLost V_Jitter
					   V_Latency ) ],
0x22  => [ OpenReceiveChannelAck    => qw( V_ORCStatus *_ipAddress V_PortNumber
                                           V_PassThruPartyID ) ],
0x21  => [ MulticastMediaReceptionAck
                                    => qw( V_ReceptionStatus V_PassThruPartyID
                                           ) ],
0x20  => [ Alarm                    => qw( V_AlarmSeverity Z80_Display
                                           V_AlarmParam1 *_AlarmParam2 ) ],
0x12  => [ ServerReq                => qw( ) ],
0x11  => [ MediaPortList            => qw( ) ],
0x10  => [ CapabilitiesRes          => qw( ) ],
0x0f  => [ VersionReq               => qw( ) ],
0x0e  => [ ButtonTemplateReq        => qw( ) ],
0x0d  => [ TimeDateReq              => qw( ) ],
0x0c  => [ ConfigStateReq           => qw( ) ],
0x0b  => [ LineStatReq              => qw( V_LineNumber ) ],
0x0a  => [ SpeedDialStatReq         => qw( V_SpeedDialNumber ) ],
0x09  => [ ForwardStatReq           => qw( V_LineNumber ) ],
0x08  => [ HookFlash                => qw( ) ],
0x07  => [ OnHook                   => qw( ) ],
0x06  => [ OffHook                  => qw( ) ], 
0x05  => [ Stimulus                 => qw( V_Stimulus V_StimulusInstance) ],
0x04  => [ EnblocCall               => qw( V_CalledParty ) ],
0x03  => [ KeypadButton             => qw( V_Button ) ],
0x02  => [ IpPort                   => qw( V_PortNumber ) ],
0x01  => [ Register                 => qw( Z16_PhoneName V_StationUserId
                                           V_StationInstance *_IPAddress
                                           V_DeviceType V_MaxStreams) ],
0     => [ KeepAlive                => qw( ) ],
);
}

