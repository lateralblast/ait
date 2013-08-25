#!/usr/bin/env perl

use strict;
use Getopt::Std;

# Name:         adicheck.pl
# Version:      0.0.6
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
my %krb5_conf_entries;
my %kdc_conf_entries;
my %sssd_conf_entries;
my %params;
my @linux_kdc_conf_entries;
my $options="Vch";

get_host_info();

if ($os_name=~/SunOS/) {
  $pam_file="/etc/pam.conf";
  @pam_entries = (
    "other[[:space:]]*auth[[:space:]]*requisite[[:space:]]*pam_authtok_get.so.1",
    "other[[:space:]]*auth[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*auth[[:space:]]*sufficient[[:space:]]*pam_unix_auth.so.1 try_first_pass",
    "other[[:space:]]*account[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*account[[:space:]]*sufficient[[:space:]]*pam_unix_account.so.1",
    "other[[:space:]]*session[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1",
    "other[[:space:]]*session[[:space:]]*sufficient[[:space:]]*pam_unix_session.so.1"
  );
  $krb5_dir          = "/etc/krb5";
  $keytab_file       = "$krb5_dir/krb5.keytab";
  $krb5_conf_file    = "$krb5_dir/krb5.conf";
  $kdc_conf_file     = "$krb5_dir/kdc.conf";
  $kadm5_keytab_file = "$krb5_dir/kadm5.keytab";
  $kadm5_acl_file    = "$krb5_dir/kadm5.acl";
  %krb5_conf_entries = (
    "default_realm"             , "$default_realm",
    "verify_ap_req_nofail"      , "false",
    "$default_realm"            , "{".
    "kdc"                       , "$kdc",
    "admin_server"              , "$admin_server",
    "$admin_server"             , "$default_realm"
  );
  %kdc_conf_entries = (
    "kdc_ports"                 , "88,750",
    "$default_realm"            , "{".
    "profile"                   , "$krb5_conf_file",
    "admin_keytab"              , "$kadm5_keytab_file",
    "acl_file"                  , "$kadm5_acl_file",
    "kadmind_port"              , "749",
    "max_life"                  , "10h 0m 0s",
    "max_renewable_life"        , "7d 0h 0m 0s",
    "default_principal_flags"   , "+preauth"
  );
  @krb5_services = (
    "svc:/network/security/ktkt_warn:default,online"
  );
}

if ($os_name=~/Linux/) {
  $pam_file="/etc/pam/system-auth-ac";
  if ($os_rel=~/^5/) {
    @pam_entries = (
      "auth[[:space:]]*required[[:space:]]*pam_env.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_unix.so nullok try_first_pass",
      "auth[[:space:]]*requisite[[:space:]]*pam_succeed_if.so uid >= 500 quiet",
      "auth[[:space:]]*required[[:space:]]*pam_deny.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "account[[:space:]]*required[[:space:]]*pam_unix.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_succeed_if.so uid < 500 quiet",
      "account[[:space:]]*required[[:space:]]*pam_permit.so",
      "password[[:space:]]*requisite[[:space:]]*pam_cracklib.so try_first_pass retry=3",
      "password[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "password[[:space:]]*sufficient[[:space:]]*pam_unix.so md5 shadow nullok try_first_pass use_authtok",
      "password[[:space:]]*required[[:space:]]*pam_deny.so",
      "session[[:space:]]*optional[[:space:]]*pam_keyinit.so revoke",
      "session[[:space:]]*required[[:space:]]*pam_limits.so",
      "session[[:space:]]*[success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid",
      "session[[:space:]]*sufficient[[:space:]]*pam_krb5.so",
      "session[[:space:]]*required[[:space:]]*pam_unix.so"
   );
  }
  if ($os_rel=~/^6/) {
    @pam_entries = (
      "auth[[:space:]]*required[[:space:]]*pam_env.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_fprintd.so",
      "auth[[:space:]]*sufficient[[:space:]]*pam_unix.so nullok try_first_pass",
      "auth[[:space:]]*requisite[[:space:]]*pam_succeed_if.so uid >= 500 quiet",
      "auth[[:space:]]*sufficient[[:space:]]*pam_sss.so use_first_pass",
      "auth[[:space:]]*required[[:space:]]*pam_deny.so",
      "account[[:space:]]*required[[:space:]]*pam_unix.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_localuser.so",
      "account[[:space:]]*sufficient[[:space:]]*pam_succeed_if.so uid < 500 quiet",
      "account[[:space:]]*[default=bad success=ok user_unknown=ignore] pam_sss.so",
      "account[[:space:]]*required[[:space:]]*pam_permit.so",
      "password[[:space:]]*requisite[[:space:]]*pam_cracklib.so try_first_pass retry=3 type=",
      "password[[:space:]]*sufficient[[:space:]]*pam_unix.so md5 shadow nullok try_first_pass use_authtok",
      "password[[:space:]]*sufficient[[:space:]]*pam_sss.so use_authtok",
      "password[[:space:]]*required[[:space:]]*pam_deny.so",
      "session[[:space:]]*optional[[:space:]]*pam_keyinit.so revoke",
      "session[[:space:]]*required[[:space:]]*pam_limits.so",
      "session[[:space:]]*[success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid",
      "session[[:space:]]*required[[:space:]]*pam_mkhomedir.so skel=/etc/skel/ umask=0077",
      "session[[:space:]]*optional[[:space:]]*pam_sss.so",
      "session[[:space:]]*required[[:space:]]*pam_unix.so"
    );
  }
  if ($os_rel=~/^6/) {
    %sssd_conf_entries = (
      "config_file_version"       , "2",
      "reconnection_retries"      , "3",
      "sbus_timeout"              , "30",
      "services"                  , "nss, pam",
      "domain"                    , "$default_realm",
      "filter_groups"             , "root",
      "filter_users"              , "root",
      "description"               , "$org_name",
      "debug_level"               , "256",
      "enumerate"                 , "false",
      "min_id"                    , "1000",
      "id_provider"               , "ldap",
      "ldap_uri"                  , "ldap://$kdc/",
      "ldap_schema"               , "rfc2307bis",
      "ldap_sasl_mech"            , "GSSAPI",
      "ldap_user_search_base"     , "$ldap_user_search_base",
      "ldap_group_search_base"    , "$ldap_group_search_base",
      "ldap_user_object_class"    , "posixAccount",
      "ldap_user_name"            , "sAMAccountName",
      "ldap_user_uid_number"      , "uidNumber",
      "ldap_user_gid_number"      , "gidNumber",
      "ldap_user_home_directory"  , "unixHomeDirectory",
      "ldap_user_shell"           , "loginShell",
      "ldap_user_principal"       , "userPrincipalName",
      "ldap_user_member"          , "msSFU30PosixMemberOf",
      "ldap_group_object_class"   , "posixGroup",
      "ldap_group_name"           , "sAMAccountName",
      "ldap_group_gid_number"     , "gidNumber",
      "ldap_group_member"         , "member",
      "auth_provider"             , "krb5"
    );
  }
  $krb5_dir          = "/etc";
  $keytab_file       = "$krb5_dir/krb5.keytab";
  $krb5_conf_file    = "$krb5_dir/krb5.conf";
  $kdc_conf_file     = "$krb5_dir/kdc.conf";
  $kadm5_keytab_file = "$krb5_dir/kadm5.keytab";
  $kadm5_acl_file    = "$krb5_dir/kadm5.acl";
  %krb5_conf_entries = (
    "default"                   , "FILE:/var/log/krb5libs.log",
    "kdc"                       , "FILE:/var/log/krb5kdc.log",
    "admin_server"              , "FILE:/var/log/kadmind.log",
    "default_realm"             , "$default_realm",
    "dns_lookup_realm"          , "false", 
    "dns_lookup_kdc"            , "false",
    "ticket_lifetime"           , "24h",
    "renew_lifetime"            , "7d",
    "forwardable"               , "true",
    "$default_realm"            , "{",
    "kdc"                       , "$kdc:88",
    "admin_server"              , "$admin_server:749",
    ".$kdc"                     , "$default_realm",
    "$kdc"                      , "$default_realm"
  );
  @linux_kdc_conf_entries = (
    "$default_realm",
    "$default_realm"."[[:space:]]*$kdc:88",
    "$default_realm"."[[:space:]]*$kdc:749 admin server",
  ); 
}

if ($#ARGV == -1) {
  print_usage();
}
else {
  getopts($options,\%option);
}

# If given -h print usage

if ($option{'h'}) {
  print_usage();
  exit;
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

if ($option{'c'}) {
  get_host_info();
  adi_check();
  exit;
}

sub handle_output {
  my $output=$_[0];
  print "$output\n";
}

sub print_usage {
  print "\n";
  print "Usage: $script_name -$options\n";
  print "\n";
  print "-V: Print version information\n";
  print "-h: Print help\n";
  print "-c: Check Active Directory (Kerberos) Integration configs\n";
  print "\n";
  return;
}

sub get_host_info {
  $os_name=`uname`;
  chomp($os_name);
  if ($os_name=~/Linux/) {
    $os_rel=`lsb_release -r |awk '{print $2}'`;
    chomp($os_rel);
  }
  return;
}

sub check_file_exists {
  my $filename=$_[0];
  if (! -f "$filename") {
    handle_output("Warning: File $filename does not exist");
    return("");
  }
  else {
    handle_output("File $filename exists");
    return($filename);
  }
}

sub check_dir_exists {
  my $dirname=$_[0];
  if (! -d "$dirname") {
    handle_output("Warning: Directory $dirname does not exist");
    return("");
  }
  else {
    handle_output("Directory $dirname exists");
    return($dirname);
  }
}

sub check_file_entries {
  my $check_file=$_[0];
  my @file_entries;
  my $entry; 
  my $info;
  my $line;
  if (-f "$check_file") {
    @file_entries=`cat $check_file`;
    foreach $entry (@conf_file_entries) {
      $info=$entry;
      $info=~s/\[\[\:space\:\]\]/ /g;
      if (grep /$entry/, @file_entries) {
        $line="File $check_file contains $info\n";
      }
      else {
        $line="Warning: File $check_file does not contain $info\n";
      }
      handle_output($line);
    }
  }
  else {
    $line="Warning: File $check_file does not contain $info\n";
    handle_output($line);
  }
  return;
}

sub check_conf_file {
  my $conf_file=$_[0];
  my @file_info;
  my $line;
  my $key;
  my $hash_param;
  my $hash_value;
  my $line_param;
  my $line_value;
  my %results;
  $conf_file=check_file_exists($conf_file);
  while (($hash_param,$hash_value)=each(%params)) {
    $results{$hash_param}=0;
  }
  if (-f "$conf_file") {
    @file_info=`cat $conf_file |grep -v '^#'`;
    foreach $line (@file_info) {
      chomp($line);
      while (($hash_param,$hash_value)=each(%params)) {
        if ($line=~/^$hash_param/) {
          $results{$hash_param}=1;
          ($line_param,$line_value)=split("=",$line);
          $line_value=~s/ //g;
          if ($line_value!~/^$hash_value/) {
            handle_output("Parameter $hash_param in $conf_file correctly set to $hash_value");
          }
        }
      }
    }
    while (($hash_param,$hash_value)=each(%results)) {
      if ($hash_value == 0) {
        handle_output("Warning: File $conf_file does not contain $hash_param = $hash_value");
      }
    }
  }
}

sub check_krb5_services {
  my $service;
  my $correct_status;
  my $status;
  foreach $service (@krb5_services) {
    ($service,$correct_status)=split(",",$service);
    if ($os_name=~/SunOS/) {
      $status=`svcs -l $service |grep '^state ' |awk '{print $1}'`;
    }
    if ($status=~/$correct_status/) {
      handle_output("Service $service is $correct_status");
    }
    else {
      handle_output("Warning: Service $service is $correct_status");
    }
  }
  return;
}

sub check_file_perms {
  my $check_file=$_[0];
  my $check_user=$_[1];
  my $check_group=$_[2];
  my $check_perm=$_[3];
  my $file_mode;
  my $file_user;
  my $file_group;
  $check_file=check_file_exists($check_file);
  if (-f "$check_file") {
    $file_mode=(stat($check_file))[2];
    $file_mode=sprintf("%04o",$file_mode & 07777);
    $file_user=(stat($check_file))[4];
    $file_group=(stat($check_file))[5];
    $file_user=getpwuid($file_user);
    if ($file_mode != $check_perm) {
      handle_output("Warning: Permission of file $check_file are not $check_perm");
    }
    else {
      handle_output("Permissions on $check_file are correctly set to $check_perm");
    }
    if ($file_user != $check_user) {
      handle_output("Warning: Ownership of file $check_file is not $check_user");
    }
    else {
      handle_output("Ownership of $check_file is correctly set to $check_user");
    }
    if ($file_group != $check_group) {
      handle_output("Warning: Group ownership of file $check_file is not $check_group");
    }
    else {
      handle_output("Group ownership of $check_file is correctly set to $check_group");
    }
  }
  return;
}

sub check_klist {
  if ($os_name=~/SunOS/) {
    system("klist -k");
  }
  else {
    system("klist -a");
  }
  return;
}

sub adi_check {
  @conf_file_entries=@pam_entries;
  check_file_entries($pam_file);
  %params=%krb5_conf_entries;
  check_conf_file($krb5_conf_file);
  if ($os_name=~/SunOS/) {
    %params=%kdc_conf_entries;
    check_conf_file($kdc_conf_file);
  }
  else {
    @conf_file_entries=@linux_kdc_conf_entries;
    check_file_entries($kdc_conf_file);
    if ($os_rel=~/^6/) {
      %params=%sssd_conf_entries;
      check_file_entries($sssd_file);  
    }
  }
  check_krb5_services();
  check_klist();
  check_file_perms($keytab_file,"root","root","0640");
  return;
}
