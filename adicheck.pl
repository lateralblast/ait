#!/usr/bin/env perl

use strict;
use Getopt::Std;

# Name:         adicheck.pl
# Version:      0.1.7
# Release:      1
# License:      Open Source 
# Group:        System
# Source:       N/A 
# URL:          N/A
# Distribution: Solaris / Linux
# Vendor:       Lateral Blast 
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to check Active Directory (Kerberos) Integration for Solaris / Linux

# Changes       0.0.1 Sat 24 Aug 2013 16:17:41 EST
#               Initial version
#               0.0.2 Sun 25 Aug 2013 08:53:18 EST
#               Added Linux support
#               0.0.3 Sun 25 Aug 2013 15:42:36 EST
#               Bug fixes
#               0.0.4 Sun 25 Aug 2013 17:21:52 EST
#               Code clean up
#               0.0.5 Mon 26 Aug 2013 07:51:36 EST
#               Added file permission check
#               0.0.6 Mon 26 Aug 2013 08:11:16 EST
#               Added group permissions check
#               0.0.7 Mon 26 Aug 2013 08:35:11 EST
#               Fixed permissions check to include directories
#               0.0.8 Mon 26 Aug 2013 10:20:04 EST
#               Cleaned up parameter checking
#               0.0.9 Mon  9 Sep 2013 10:12:00 EST
#               Added fix/install and uninstall capability
#               0.1.0 Mon  9 Sep 2013 11:38:12 EST
#               Updated documentation
#               0.1.1 Mon  9 Sep 2013 17:04:26 EST
#               Updated krb5.conf handling
#               0.1.2 Mon  9 Sep 2013 18:04:26 EST
#               Fixed bug with updating files
#               0.1.3 Mon  9 Sep 2013 18:40:39 EST
#               Small code cleanup
#               0.1.4 Mon  9 Sep 2013 18:49:43 EST
#               Fixed bugs
#               0.1.5 Mon  9 Sep 2013 23:23:08 EST
#               More bug fixes
#               0.1.6 Tue 10 Sep 2013 13:49:23 EST
#               Got rid of hashes
#               0.1.7 Tue 10 Sep 2013 14:07:31 EST
#               Added check to make sure Organisation details are set

my $script_name=$0;
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`; 
my %option=();
my $os_name;
my @pam_entries;
my $krb5_dir;
my $krb5_conf_file;
my $kdc_conf_file;
my $kadm5_keytab_file;
my $kadm5_acl_file;
my $default_realm;
my $kdc;
my $org_name                = "Blah Australia";
my $ldap_user_search_base   = "";
my $ldap_group_search_base  = "";
my $default_realm           = "BLAH.COM";
my $kdc                     = lc($default_realm);
my $admin_server            = lc($default_realm);
my $sssd_file               = "/etc/sssd/sssd.conf";
my $keytab_file;
my @krb5_services;
my $pam_file;
my @conf_file_entries;
my $os_rel;
my @krb5_conf_entries;
my @kdc_conf_entries;
my @sssd_conf_entries;
my $options="Vchsfiu";

get_host_info();

if ($os_name=~/SunOS/) {
  $pam_file="/etc/pam.conf";
  # Create an array of correct settings for PAM
  @pam_entries = (
    "",
    "other[[:space:]]*auth[[:space:]]*requisite[[:space:]]*pam_authtok_get.so.1",
    "other[[:space:]]*auth[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*auth[[:space:]]*sufficient[[:space:]]*pam_unix_auth.so.1 try_first_pass",
    "other[[:space:]]*account[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*account[[:space:]]*sufficient[[:space:]]*pam_unix_account.so.1",
    "other[[:space:]]*session[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*session[[:space:]]*sufficient[[:space:]]*pam_unix_session.so.1",
    ""
  );
  $krb5_dir          = "/etc/krb5";
  $keytab_file       = "$krb5_dir/krb5.keytab";
  $krb5_conf_file    = "$krb5_dir/krb5.conf";
  $kdc_conf_file     = "$krb5_dir/kdc.conf";
  $kadm5_keytab_file = "$krb5_dir/kadm5.keytab";
  $kadm5_acl_file    = "$krb5_dir/kadm5.acl";
  # Correct state for service
  @krb5_services = (
    "svc:/network/security/ktkt_warn:default,online"
  );
}

if ($os_name=~/Linux/) {
  $pam_file="/etc/pam.d/system-auth-ac";
  if ($os_rel=~/^5/) {
    # Create an array of correct settings for PAM
    @pam_entries = (
      "",
      "auth[[:space:]]*required[[:space:]]*pam_env.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_unix.so nullok try_first_pass",
      "auth[[:space:]]*requisite[[:space:]]*pam_succeed_if.so uid >= 500 quiet",
      "auth[[:space:]]*required[[:space:]]*pam_deny.so",
      "",
      "account[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "account[[:space:]]*required[[:space:]]*pam_unix.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_succeed_if.so uid < 500 quiet",
      "account[[:space:]]*required[[:space:]]*pam_permit.so",
      "",
      "password[[:space:]]*requisite[[:space:]]*pam_cracklib.so try_first_pass retry=3",
      "password[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "password[[:space:]]*sufficient[[:space:]]*pam_unix.so md5 shadow nullok try_first_pass use_authtok",
      "password[[:space:]]*required[[:space:]]*pam_deny.so",
      "",
      "session[[:space:]]*optional[[:space:]]*pam_keyinit.so revoke",
      "session[[:space:]]*required[[:space:]]*pam_limits.so",
      "session[[:space:]]*\\[success=1 default=ignore\\] pam_succeed_if.so service in crond quiet use_uid",
      "session[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "session[[:space:]]*required[[:space:]]*pam_unix.so",
      ""
   );
  }
  if ($os_rel=~/^6/) {
    # Create an array of correct settings for PAM
    @pam_entries = (
      "",
      "auth[[:space:]]*required[[:space:]]*pam_env.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_fprintd.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_unix.so nullok try_first_pass",
      "auth[[:space:]]*requisite[[:space:]]*pam_succeed_if.so uid >= 500 quiet",
      "auth[[:space:]]*sufficient[[:space:]]*pam_sss.so use_first_pass",
      "auth[[:space:]]*required[[:space:]]*pam_deny.so",
      "",
      "account[[:space:]]*required[[:space:]]*pam_unix.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_localuser.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_succeed_if.so uid < 500 quiet",
      "account[[:space:]]*[default=bad success=ok user_unknown=ignore] pam_sss.so",
      "account[[:space:]]*required[[:space:]]*pam_permit.so",
      "",
      "password[[:space:]]*requisite[[:space:]]*pam_cracklib.so try_first_pass retry=3 type=",
      "password[[:space:]]*sufficient[[:space:]]*pam_unix.so md5 shadow nullok try_first_pass use_authtok",
      "password[[:space:]]*sufficient[[:space:]]*pam_sss.so use_authtok",
      "password[[:space:]]*required[[:space:]]*pam_deny.so",
      "",
      "session[[:space:]]*optional[[:space:]]*pam_keyinit.so revoke",
      "session[[:space:]]*required[[:space:]]*pam_limits.so",
      "session[[:space:]]*[success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid",
      "session[[:space:]]*required[[:space:]]*pam_mkhomedir.so skel=/etc/skel/ umask=0077",
      "session[[:space:]]*optional[[:space:]]*pam_sss.so",
      "session[[:space:]]*required[[:space:]]*pam_unix.so",
      ""
    );
  }
  if ($os_rel=~/^6/) {
    @sssd_conf_entries = (
      "",
      "[sssd]",
      "config_file_version = 2",
      "reconnection_retries = 3",
      "sbus_timeout = 30",
      "services = nss, pam",
      "domain = $default_realm",
      "",
      "[nss]",
      "filter_groups = root",
      "filter_users = root",
      "",
      "[pam]",
      "reconnection_retries = 3",
      "",
      "[domain/$default_realm]",
      "debug_level = 256",
      "description = $org_name",
      "enumerate = false",
      "min_id = 1000",
      "id_provider = ldap",
      "ldap_uri = ldap://$kdc/",
      "ldap_schema = rfc2307bis",
      "ldap_sasl_mecho = GSSAPI",
      "ldap_user_search_base = $ldap_user_search_base",
      "ldap_group_search_base = $ldap_group_search_base",
      "",
      "ldap_user_object_class = posixAccount",
      "ldap_user_name = sAMAccountName",
      "ldap_user_uid_number = uidNumber",
      "ldap_user_gid_number = gidNumber",
      "ldap_user_home_directory = unixHomeDirectory",
      "ldap_user_shell = loginShell",
      "ldap_user_principal = userPrincipalName",
      "ldap_user_member = msSFU30PosixMemberOf",
      "",
      "ldap_group_object_class = posixGroup",
      "ldap_group_name = sAMAccountName",
      "ldap_group_gid_number = gidNumber",
      "ldap_group_member = member",
      "",
      "auth_provider = krb5",
      "chpass_provider = krb5",
      "krb5_realm = $default_realm",
      "krb5_server = $kdc",
      "krb5_canonicalize = false",
      "ldap_force_upper_case_realm = true"
    );
  }
  $krb5_dir          = "/etc";
  $keytab_file       = "$krb5_dir/krb5.keytab";
  $krb5_conf_file    = "$krb5_dir/krb5.conf";
  $kdc_conf_file     = "$krb5_dir/kdc.conf";
  $kadm5_keytab_file = "$krb5_dir/kadm5.keytab";
  $kadm5_acl_file    = "$krb5_dir/kadm5.acl";
  # Create an array for correct values for kdc.conf
  @kdc_conf_entries = (
    "$default_realm",
    "$default_realm"."[[:space:]]*$kdc:88",
    "$default_realm"."[[:space:]]*$kdc:749 admin server",
  ); 
}

if ($os_name=~/Linux/) {
  # Create an array of entries for krb5.conf
  @krb5_conf_entries = (
    "",
    "[logging]",
    "default = FILE:/var/log/krb5libs.log",
    "kdc = FILE:/var/log/krb5kdc.log",
    "admin_server = FILE:/var/log/kadmind.log",
    "",
    "[libdefaults]",
    "default_realm = $default_realm",
    "dns_lookup_realm = false",
    "dns_lookup_kdc = false",
    "ticket_lifetime = 24h",
    "renew_lifetime = 7d",
    "forwardable = true",
    "",
    "[realms]",
    "$default_realm = {",
    "kdc = $kdc",
    "admin_server = $admin_server",
    "}",
    "",
    "[domain_realm]",
    ".kdc = $default_realm",
    "kdc = $default_realm"
  );
}
if ($os_name=~/SunOS/) {
  # Create an array of entries for krb5.conf
  @krb5_conf_entries = (
    "",
    "[libdefaults]",
    "    default_realm = $default_realm",
    "    verify_ap_req_nofail = false",
    "",
    "[realms]",
    "    $default_realm = {",
    "        kdc = $kdc",
    "        admin_server = $admin_server",
    "    }",
    "",
    "[domain_realm]",
    "    .$kdc = $default_realm",
    "",
    "[logging]",
    "    default = FILE:/var/krb5/kdc.log",
    "    kdc = FILE:/var/krb5/kdc.log",
    "    kdc_rotate = {",
    "        period = 1d",
    "        versions = 10",
    "     }",
    "",
    "[appdefaults]",
    "    kinit = {",
    "        renewable = true",
    "        forwardable= true",
    "    }",
    "    gkadmin = {",
    "        help_url = http://docs.sun.com:80/ab2/coll.384.1/SEAM/\@AB2PageView/1195",
    "    }"
  );
}

if ($#ARGV == -1) {
  print_usage();
  exit;
}
else {
  getopts($options,\%option);
}

# If given -h print usage

if ($option{'h'}) {
  print_usage();
  exit;
}

# Check whether Organisation details are set

if ((!$option{'h'})||($option{'V'})) {
  if ($org_name=~/Blah/) {
    print "Set the Organisation details and rerun script\n";
    exit;
  }
}

sub print_version {
  print "$script_version";
  return;
}

# Print script version

if ($option{'V'}) {
  print_version();
  exit;
}

# Run check

if (($option{'c'})||($option{'f'})||($option{'i'})||($option{'u'})) {
  if ($option{'i'}) {
    $option{'f'}=1;
  }
  get_host_info();
  adi_check();
  exit;
}

# Subrouting to print usage information

sub print_usage {
  print "\n";
  print "Usage: $script_name -$options\n";
  print "\n";
  print "-V: Print version information\n";
  print "-h: Print help\n";
  print "-s: Check server (KDC config)\n";
  print "-c: Check Active Directory (Kerberos) Integration configs\n";
  print "-f: Fix Active Directory (Kerberos) Integration configs\n";
  print "-i: Install Active Directory (Kerberos) Integration configs\n";
  print "-u: Undo Active Directory (Kerberos) Integration configs\n";
  print "\n";
  return;
}

# Subroutine to get host information

sub get_host_info {
  $os_name=`uname`;
  chomp($os_name);
  if ($os_name=~/Linux/) {
    $os_rel=`lsb_release -r |awk '{print \$2}'`;
    chomp($os_rel);
  }
  return;
}

# Subrouting to check a file exists

sub check_file_exists {
  my $filename=$_[0];
  if (! -f "$filename") {
    print "Warning: File \"$filename\" does not exist\n";
    return("");
  }
  else {
    print "File \"$filename\" exists\n";
    return($filename);
  }
}

# Subroutine to check a directory exists

sub check_dir_exists {
  my $dirname=$_[0];
  if (! -d "$dirname") {
    print "Warning: Directory \"$dirname\" does not exist\n";
    return("");
  }
  else {
    print "Directory \"$dirname\" exists\n";
    return($dirname);
  }
}

# Subroutine to check entries for a config file

sub check_file_entries {
  my $check_file=$_[0];
  my @file_entries;
  my $entry; 
  my $info;
  my $line;
  my $correct=1;
  if (-f "$check_file") {
    # check entries in the file against the correct values in the array
    @file_entries=`cat $check_file |grep -v '^#'`;
    foreach $entry (@conf_file_entries) {
      $info=$entry;
      $info=~s/\[\[\:space\:\]\]\*/ /g;
      if ($info!~/^$/) {
        if (grep /$entry/, @file_entries) {
          print "File \"$check_file\" contains \"$info\"\n";
        }
        else {
          $correct=0;
          print "Warning: File \"$check_file\" does not contain \"$info\"\n";
        }
      }
    }
  }
  else {
    print "Warning: File \"$check_file\" does not contain \"$info\"\n";
  }
  # If we enconunter a value that is not set correctly and we are in
  # fix mode, backup the file, zero it out and dump correct values into it
  if ($option{'f'}) {
    if ($correct eq 0) {
      if (-f "$check_file") {
        print "Backing up $check_file to $check_file.pread\n";
        system("cp $check_file $check_file.pread");
      }
      if ($os_name=~/Linux/) {
        print "Creating $check_file\n";
        system("cat /dev/null > $check_file");
      }
      else {
        if ($check_file=~/$pam_file/) {
          system("cat $check_file.pread |grep -v '^other' > $check_file");
        }
        print "Updating $check_file\n";
      }
      open(OUTPUT,">>",$check_file);
      foreach $entry (@conf_file_entries) {
        $line=$entry;
        $line=~s/\[\[\:space\:\]\]\*/\t/g;
        print OUTPUT "$line\n";
      }
      close(OUTPUT);
    }
  }
  # To undo AD check if pread file exists, if so cat it's contents into
  # config file and remove it
  if ($option{'u'}) {
    if (-f "$check_file.pread") {
      print "Restoring original $check_file\n";
      system("cat $check_file.pread > $check_file");
      system ("rm $check_file.pread");
    }
  }
  return;
}

# Subroutine to check status of required services

sub check_krb5_services {
  my $service;
  my $correct_status;
  my $status;
  foreach $service (@krb5_services) {
    ($service,$correct_status)=split(",",$service);
    if ($os_name=~/SunOS/) {
      $status=`svcs -l $service |grep '^state ' |awk '{print \$2}'`;
    }
    if ($status=~/$correct_status/) {
      # If we are uninstalling stop service
      print "Service $service is \"$correct_status\"\n";
      if ($option{'u'}) {
        print "Disabling $service\n";
        if ($os_name=~/SunOS/) {
          system("svcadm disable $service");
        }
        else {
          system("/sbin/service $service stop");
          system("/sbin/chkconfig $service off");
        }
      }
    }
    else {
      # If we are fixing or installing start service
      print "Warning: Service \"$service\" is not \"$correct_status\"\n";
      if ($option{'f'}) {
        if ($os_name=~/SunOS/) {
          system("svcadm enable $service");
        }
        else {
          system("/sbin/chkconfig $service on");
          system("/sbin/service $service start");
        }
      }
    }
  }
  return;
}

# Subroutine to check file permissions and ownerships

sub check_file_perms {
  my $check_file=$_[0];
  my $check_user=$_[1];
  my $check_group=$_[2];
  my $check_perm=$_[3];
  my $file_mode;
  my $file_user;
  my $file_group;
  $check_file=check_file_exists($check_file);
  if ((-f "$check_file")||(-d "$check_file")) {
    $file_mode=(stat($check_file))[2];
    $file_mode=sprintf("%04o",$file_mode & 07777);
    $file_user=(stat($check_file))[4];
    $file_group=(stat($check_file))[5];
    $file_user=getpwuid($file_user);
    if ($file_mode != $check_perm) {
      print "Warning: Permissions on \"$check_file\" are not \"$check_perm\"\n";
      print "Warning: Permissions nf $check_file are not $check_perm\n";
      if ($option{'f'}) {
        print "Fixing permissions on $check_file\n";
        system("chmod $check_perm $check_file");
      }
    }
    else {
      print "Permissions on \"$check_file\" are correctly set to \"$check_perm\"\n";
    }
    if ($file_user != $check_user) {
      print "Warning: Ownership of \"$check_file\" is not \"$check_user\"\n";
      if ($option{'f'}) {
        print "Fixing ownership of $check_file\n";
        system("chown $check_user $check_file");
      }
    }
    else {
      print "Ownership of \"$check_file\" is correctly set to \"$check_user\"\n";
    }
    if ($file_group != $check_group) {
      print "Warning: Group ownership of \"$check_file\" is not \"$check_group\"\n";
      if ($option{'f'}) {
        print "Fixing group ownership on $check_file\n";
        system("chgrp $check_group $check_file");
      }
    }
    else {
      print "Group ownership of \"$check_file\" is correctly set to \"$check_group\"\n";
    }
  }
  return;
}

# Subroutine to check we've got tickets

sub check_klist {
  if ($os_name=~/SunOS/) {
    system("klist -k");
  }
  else {
    system("klist -a");
  }
  return;
}

# Main subroutine

sub adi_check {
  @conf_file_entries=@pam_entries;
  check_file_entries($pam_file);
  @conf_file_entries=@krb5_conf_entries;
  check_file_entries($krb5_conf_file);
  if ($os_name=~/Linux/) {
    if ($os_rel=~/^6/) {
      @conf_file_entries=@sssd_conf_entries;
      check_file_entries($sssd_file);  
    }
  }
  if ($option{'s'}) {
    @conf_file_entries=@kdc_conf_entries;
    check_file_entries($kdc_conf_file);
  }
  check_krb5_services();
  check_klist();
  check_file_perms($keytab_file,"root","root","0600");
  return;
}
