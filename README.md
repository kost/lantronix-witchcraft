lantronix-witchcraft
====================

Perl utilities to retrieve and/or set basic and enhanced telnet passwords (amongst others)

Requirements
====================
- Perl

Options
====================
 -Q	query device (MAC address and type)
 -G	get setup records (try all records)
 -P	get simple password
 -R	reset simple password to null (password will be disabled)
 -C	query device for version (password leak sometimes)
 -E	reset security record (includes enhanced password and AES)
 -S	reset security record (includes enhanced password but not AES)
 -F <s>	set simple password to <s>
 -i <s>	connect to IP <s>
 -I <s>	use IP addresses from file <s> (IP address per line)
 -Y	dry run (don't send any packets)
 -b	send broadcast packet
 -t	add timestamp
 -p <d>	use port <d> (default: 30718)
 -v	verbose (-vvvvv will be more verbose)
 -h	this help

Example: 
    ./lantronix-witchcraft.pl -Q -C 127.0.0.1
Example: 
     ./lantronix-witchcraft.pl -P -E 127.0.0.1


