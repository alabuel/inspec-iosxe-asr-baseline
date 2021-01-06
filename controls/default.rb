#_-----------------------------------------------------------____________
# Variable assignment
# -----------------------------------------------------------

BANNER = attribute('BANNER', value: ['WARNING: Use of this System is restricted to authorised users only. User activity may be monitored and/or recorded. Anyone using this System expressly consents to such monitoring and/or recording. If possible criminal activity is detected, these records, along with certain personal information, may be provided to law enforcement officials.'])
ENCRYPTION = attribute('ENCRYPTION', value: 'AES256')
SSH_AUTH_TIMEOUT = attribute('SSH_AUTH_TIMEOUT', value: 900)
SSH_AUTH_RETRIES = attribute('SSH_AUTH_RETRIES', value: 3)
LOGGING_BUFFER = attribute('LOGGING_BUFFER', value: 64000)
EXTERNAL_INTERFACES = attribute('EXTERNAL_INTERFACES', value: [])
EIGRP_INTERFACE = attribute('EIGRP_INTERFACE', value: '')
OSPF_INTERFACE = attribute('OSPF_INTERFACE', value: '')
RIP_INTERFACE = attribute('RIP_INTERFACE', value: '')
NA_BASELINE_SETTINGS = attribute('NA_BASELINE_SETTINGS', value: ['4.2.5','5.4.4','6.3.2.1','6.3.2.2','6.3.2.4','6.3.2.5','6.3.2.6','6.3.4.1','6.3.4.2'])
ISP_COMPARTMENT = attribute('ISP_COMPARTMENT', value: false)
IGWC_COMPARTMENT = attribute('IGWC_COMPARTMENT', value: false)

# -----------------------------------------------------------
# 4.1 Authentication, Authorization and Accounting (AAA)
# -----------------------------------------------------------

control 'ccis_4.1.1_Enable_AAA_Service' do
  title 'Globally enable authentication, authorization and accounting (AAA) using new-model command'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^aaa new-model$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.1' }
end

control 'ccis_4.1.2_AAA_Authentication_for_Login' do
  title 'Configure TACACS+ to Authorised TACACS+ servers'
  desc 'Configure TACACS+ to authorised TACACS+ servers'

  impact 1.0
  tag cis: '1.1.2'

  describe cisco_ios_running_config do
    it { should have_line /^aaa authentication login.*/ }
  end
  describe cisco_ios_running_config do
    it { should have_line /tacacs/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.2' }
end

control 'ccis_4.1.3_AAA_Authentication_for_Enable_Mode' do
  title 'Configure AAA authentication method(s) for enable authentication'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.3'

  describe cisco_ios_running_config do
    it { should have_line /^aaa authentication enable.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.3' }
end

control 'ccis_4.1.4_AAA_Authentication_for_Local_Console_0' do
  title 'Configure management lines of console interfact to require login using the default or a named AAA authentication list'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.4'

  describe cisco_ios_running_config(section: 'line con 0') do
    it { should have_line /login authentication/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.4' }
end

control 'ccis_4.1.5_AAA_Authentication_for_line_VTY' do
  title 'Configure management lines of vty 0 to 4 to require login using the default or a named AAA authentication list'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.6'

  describe cisco_ios_running_config(section: 'line vty 0 4') do
    it { should have_line /login authentication/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.5' }
end

control 'ccis_4.1.6_Require_AAA_Accounting_Commands' do
  title 'Configure AAA accounting for commands'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.7'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting commands.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.6' }
end

control 'ccis_4.1.7_Require_AAA_Accounting_Connections' do
  title 'Configure AAA accounting for connections'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.8'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting connection.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.7' }
end

control 'ccis_4.1.8_Require_AAA_Accounting_Exec' do
  title 'Configure AAA accounting for exec'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.9'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting exec.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.8' }
end

control 'ccis_4.1.9_Require_AAA_Accounting_Network' do
  title 'Configure AAA accounting for network events'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.10'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting network.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.9' }
end

control 'ccis_4.1.10_Require_AAA_Accounting_System' do
  title 'Configure AAA accounting for system events'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.1.11'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting system.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.10' }
end

# -----------------------------------------------------------
# 4.2 Access Rules
# -----------------------------------------------------------

control 'ccis_4.2.1_VTY_Transport_SSH' do
  title 'Apply transport SSH on all management lines of VTY 0 - 4'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.2'

  describe cisco_ios_running_config(section: 'line vty 0 4') do
    it { should have_line /transport input ssh/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.1' }
end

control 'ccis_4.2.2_Forbid_Auxiliary_Port' do
  title 'Disable the EXEC process on the auxiliary port'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.3'

  describe.one do
    describe cisco_ios_running_config(section: 'line aux') do
      it { should be_empty }
    end
    describe cisco_ios_running_config(section: 'line aux') do
      it { should have_line /no exec/ }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.2' }
end

control 'ccis_4.2.3_VTY_ACL' do
  title 'Configure the VTY ACL that will be used to restrict management access to the device and allow only authorized management servers'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.4'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /access-class [\d\w]+ in/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.3' }
end

control 'ccis_4.2.4_VTY_Access_Control' do
  title 'Configure remote management access control restrictions for all VTY lines'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.5'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /access-class [\d\w]+ in/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.4' }
end

control 'ccis_4.2.5_Timeout_for_aux_0' do
  title 'Configure device timeout to disconnect sessions after 15 minutes idle time'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.6'

  describe cisco_ios_running_config(section: 'line aux 0') do
    it { should have_line /exec-timeout (15|\d) \d{1,2}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.5' }
end

control '4.2.6_Ensure_console_session_timeout_is_less_than_or_equal_to_15_minutes' do
  title 'Configure device timeout to disconnect sessions after 15 minutes idle time'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.7'

  describe cisco_ios_running_config(section: 'line con 0') do
    it { should have_line /exec-timeout (15|\d) \d{1,2}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.6' }
end

control '4.2.7_Timeout_for_line_vty' do
  title 'Configure device timeout to disconnect sessions after 15 minutes idle time'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.8'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /exec-timeout (15|\d) \d{1,2}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.7' }
end

control '4.2.8_Ensure_unused_interfaces_is_disabled' do
  title 'Disable unused interfaces'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.2.10'

  describe cisco_ios_running_config(section: 'aux 0') do
    it { should have_line /transport input none.*/ }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '4.2.8' }
end

# -----------------------------------------------------------
# 4.3 Banner Rules
# -----------------------------------------------------------

control '4.3.1_Ensure_EXEC_Banner_is_set' do
  title 'Configure the EXEC banner presented to a used when accessing the devices; before the enable prompt is diplayed, after starting an EXEC process, normally after displaying the message of the day and login banners and after the user logs into the device and authorized EXEC banner is defined'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.3.1'

  describe cisco_ios_running_config(section: 'banner exec') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.3.1' }
end

control '4.3.2_Ensure_Login_Banner' do
  title 'Configure the login banner presented to a user attempting to access the device. Presentation of the login banner occurs before the display of login prompts and usually appears after the message of the day banner and authorized login banner is defined'
  desc 'Configure banner as follows:
    WARNING: Use of this System is restricted to authorised users only.  User activity may be monitored and/or recorded. Anyone using this System expressly consents to such 
    monitoring and/or recording. If possible criminal activity is detected, these records, along with certain personal information, may be provided to law enforcement officials.
  '
  impact 1.0
  tag cis: '1.3.2'

  describe cisco_ios_running_config(section: 'banner login') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.3.2' }
end

control '4.3.3_MOTD_Banner' do
  title 'Configure the message of the day (MOTD) banner presented when a user first connects to the device. Presentation of the MOTD banner occurs before displaying the login banner and login prompt and authorized login banner is defined'
  desc 'Configure banner as follows:
    WARNING: Use of this System is restricted to authorised users only.  User activity may be monitored and/or recorded. Anyone using this System expressly consents to such 
    monitoring and/or recording. If possible criminal activity is detected, these records, along with certain personal information, may be provided to law enforcement officials.
  '
  impact 1.0
  tag cis: '1.3.3'

  describe cisco_ios_running_config(section: 'banner motd') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.3.3' }
end

# -----------------------------------------------------------
# 4.4 Password Rules
# -----------------------------------------------------------

control '4.4.1 Password Length' do
  title 'Password Length'
  desc '
      >= 16 characters

    Enforce passwords contain characters from at least tow of the following four categories:
      i.   Upper case (A through Z)
      ii.  Lower case (a through z)
      iii. Digits (0-9)
      iv.  Special Characters (!, $, #, %, etc.)
  '

  impact 1.0
  tag cis: 'none'

  describe cisco_ios_running_config(includes: 'password') do
    it { should have_line /.+/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.1' }
end

control '4.4.2 Password History' do
  title '>= passwords remembered'
  desc 'Local password will create manually as per standard operating procedure'

  impact 0
  tag cis: 'none'

  describe '4.4.2 Password History' do
    skip 'Local password will create manually as per standard operating procedure'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.2' }
end

control '4.4.3 Maximum Password Age' do
  title '1 year (365 days) Will change password manually using operation process'
  desc 'Local password will create manually as per standard operating procedure'

  impact 0
  tag cis: 'none'

  describe '4.4.3 Maximum Password Age' do
    skip 'Local password will create manually as per standard operating procedure'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.3' }
end

control '4.4.4 Enable Secret' do
  title 'Enable secret password is defined using strong encryption to protect access to privileged EXEC mode (enable mode) which is used to configure the device'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.4.1'

  describe cisco_ios_running_config do
    it { should have_line /^enable secret.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.4' }
end

control '4.4.5 Password Encryption Service' do
  title 'Enable password encryption service'
  desc 'This service ensures passwords are rendered as encrypted strings preventing an attacker from easily determining the configured value. When not enabled, many of the device’s passwords will be rendered in plain text in the configuration file'

  impact 1.0
  tag cis: '1.4.2'

  describe cisco_ios_running_config do
    it { should have_line /^service password-encryption.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.5' }
end

control '4.4.6 Username secret for all local users' do
  title 'The username secret command provides an additional layer of security over the username password'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.4.3'

  describe cisco_ios_running_config do
    it { should have_line /^username\s+\w+\s+privilege\s+\d+\s+secret.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.6' }
end

# -----------------------------------------------------------
# 4.5 SNMP Rules
# -----------------------------------------------------------

control '4.5.1 Forbid SNMP server' do
  title 'If not in use, disable simple network management protocol (SNMP), read and write access'
  desc 'Only SNMP read-only access will be enabled as required'

  impact 1.0
  tag cis: '1.5.1'

  describe cisco_ios_snmp_communities.where { name =~ /.*/ } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.1' }
end

control '4.5.2 Forbid SNMP Community String private' do
  title 'Disable the default SNMP community string "private". The default community string "private" is well known. Using easy to guess, well known community string poses a threat that an attacker can effortlessly gain aunauthorized access to the device'
  desc 'Configuration does not contain default simple network management protocol (SNMP) community strings. The configuration cannot include snmp-server community commands with prohibited community strings'

  impact 1.0
  tag cis: '1.5.2'

  describe cisco_ios_snmp_communities.where { name =~ /[Pp]rivate/ } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.2' }
end

control '4.5.3 Forbid SNMP Community String public' do
  title 'Disable the default SNMP community string "public". The default community string "public" is well known. Using easy to guess, well known community string poses a threat that an attacker can effortlessly gain aunauthorized access to the device'
  desc 'Configuration does not contain default simple network management protocol (SNMP) community strings. The configuration cannot include snmp-server community commands with prohibited community strings'

  impact 1.0
  tag cis: '1.5.3'

  describe cisco_ios_snmp_communities.where { name =~ /[Pp]ublic/ } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.3' }
end

control '4.5.4 Forbid SNMP Write Access' do
  title 'Disable SNMP write access'
  desc 'The device does not allow simple network management protocol (SNMP) write access'

  impact 1.0
  tag cis: '1.5.4'

  describe cisco_ios_snmp_communities.where { storage_type == 'RW' } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.4' }
end

control '4.5.5 Defines a SNMP ACL' do
  title 'Configure SNMP ACL for restricting access to the device from authorized management stations segmented in a trusted management zone'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.5.4'

  describe cisco_ios_snmp_communities.where { access_list =~ /.*/ } do
    its('entries.length') { should be >= 1 }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.5' }
end

control '4.5.6 SNMP Trap Server When Using SNMP' do
  title 'Configure authorized SNMP trap community string and restrict sending messages to authorized management systems'
  desc 'The device is configured to submit SNMP traps only to authorized systems required to manage the device'

  impact 1.0
  tag cis: '1.5.7'

  describe cisco_ios_snmp do
    its('hosts') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.6' }
end

control '4.5.7 Allow SNMP Traps on, when SNMP Trap server defined' do
  title 'Ensure SNMP traps are enable'
  desc 'The device is configured to send SNMP traps'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_running_config do
    it { should have_line /snmp-server enable traps/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.7' }
end

control '4.5.8 Group for SNMPv3 Access' do
  title 'Create SNMPv3 group (Do not allow plaintext SNMPv3 access)'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_snmp_groups.where { security_model !~ /v3/ } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.8' }
end

control '4.5.9 AES256 or Better Encryption for SNMPv3 Access' do
  title 'Create SNMPv3 user with authentication and encryption options. AES256 is the minimum strength encryption method that should be deployed'
  desc 'Do not allow plaintext SNMPv3 access'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_snmp_users.where { privacy_protocol == 'AES256' } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.9' }
end

# -----------------------------------------------------------
# 5.1 Global Service Rule
# -----------------------------------------------------------

control '5.1.1 Configure the Host Name' do
  title 'Configure an appropriate host name for the router. The host name is a prerequisite for setting up SSH'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^hostname .*$/ }
  end
  describe cisco_ios_running_config do
    it { should_not have_line /hostname [Rr]outer/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.1' }
end

control '5.1.2 Configure the Domain Name' do
  title 'Configure an appropriate domain name for the router.'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.2'

  describe cisco_ios_running_config do
    it { should have_line /^ip domain name .*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.2' }
end

control '5.1.3 Generate the RSA Key Pair' do
  title 'Generate an RSA key pair for the router. An RSA key pair is a prerequisite for setting up SSHand should be at least 2048 bits'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.3'

  describe cisco_ios_running_config(includes: 'crypto key') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.3' }
end

control '5.1.4 Configure the SSH Timeout' do
  title 'Configure device SSH timeout to disconnect sessions after 15 minutes idle time'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.4'

  describe cisco_ios_file_output('show_ip_ssh', includes: 'timeout') do
    it { should have_line /^Authentication timeout: #{SSH_AUTH_TIMEOUT} secs;.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.4' }
end

control '5.1.5 Limit the number of SSH Authentication Retries' do
  title 'Device is configured to limit the number of SSH authentication attempts. Retry attempts minimally must be set 3 attempts'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.5'

  describe cisco_ios_file_output('show_ip_ssh', includes: 'retries') do
    it { should have_line /^.*Authentication retries: #{SSH_AUTH_RETRIES}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.5' }
end

control '5.1.6 Ensure SSH version 2 is enabled' do
  title 'Configure the router to use SSH version 2'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.2'

  describe cisco_ios_running_config do
    it { should have_line 'ip ssh version 2' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.6' }
end

control '5.1.7 Forbid CDP Run Globally' do
  title 'Disable Cisco Discovery Protocol (CDP) service at device level'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.2'

  describe cisco_ios_file_output('show_cdp') do
    it { should have_line /^.*CDP is not enabled$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.7' }
end

control '5.1.8 Forbid IP BOOTP Server' do
  title 'Disable the bootp server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.3'

  describe cisco_ios_running_config do
    it { should have_line 'no ip bootp server' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.8' }
end

control '5.1.9 Forbid DHCP Server Service' do
  title 'Disable the DHCP server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.4'

  describe cisco_ios_running_config do
    it { should have_line 'no service dhcp' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.9' }
end

control '5.1.10 Forbid Identification Server' do
  title 'Disable the Ident server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.5'

  describe cisco_ios_running_config do
    it { should_not have_line /^ip identd$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.10' }
end

control '5.1.11 Require TCP keepalives-in Service' do
  title 'Enable TCP keepalives-in service to kill sessions where the remote side has died'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.6'

  describe cisco_ios_running_config do
    it { should have_line 'service tcp-keepalives-in' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.11' }
end

control '5.1.12 Require TCP keepalives-out Service' do
  title 'Enable TCP keepalives-out service to kill sessions where the remote side has died'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.7'

  describe cisco_ios_running_config do
    it { should have_line 'service tcp-keepalives-out' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.12' }
end

control '5.1.13 Forbid PAD Service' do
  title 'Disable the PAD service'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.8'

  describe cisco_ios_running_config do
    it { should have_line 'no service pad' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.13' }
end

# -----------------------------------------------------------
# 5.2 Logging Rules
# -----------------------------------------------------------

control '5.2.1 System Logging' do
  title 'Enable logging to allow monitoring of both operational and security related design'
  desc 'Logging is enabled to allow monitoring of both operational and security related events'

  impact 1.0
  tag cis: '2.2.1'

  describe cisco_ios_running_config do
    it { should_not have_line 'no logging on' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.1' }
end

control '5.2.2 Logging Buffer' do
  title 'Configure buffered logging (with minimum size). Recommended size is 64000 or above'
  desc 'Buffered logging (with minimum size) is configured to enable logging to internal device memory buffer'

  impact 1.0
  tag cis: '2.2.2'

  describe cisco_ios_running_config do
    it { should have_line /^logging buffered #{LOGGING_BUFFER}$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.2' }
end

control '5.2.3 Logging to Device Console' do
  title 'Configure console logging level. Note: CIS recommends critical level'
  desc 'Logging to device console is enabled and limited to a rational severity level to avoid impacting system performance and management'

  impact 1.0
  tag cis: '2.2.3'

  describe cisco_ios_running_config do
    it { should have_line /^logging console (critical|informational)$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.3' }
end

control '5.2.4 Logging to Syslog Server' do
  title 'Designate one or more authorized syslog servers by IP address'
  desc 'Set syslog server to send trap'

  impact 1.0
  tag cis: '2.2.4'

  describe cisco_ios_running_config do
    it { should have_line /^logging host\s+\d+\.\d+\.\d+\.\d+.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.4' }
end

control '5.2.5 Logging Trap Severity Level' do
  title 'Configure SNMP trap and syslog logging. Note: CIS recommends informational level'
  desc 'Simple network management protocol (SNMP) trap and syslog are set to required level'

  impact 1.0
  tag cis: '2.2.5'

  describe cisco_ios_file_output('show_log', includes: 'Trap logging') do
    it { should have_line /^.*Trap logging:\s+level\s(informational|debugging)/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.5' }
end

control '5.2.6 Service Timestamps for Debug and Log Messages' do
  title 'Configure debug and Log messages to include timestamps'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.2.6'

  describe cisco_ios_running_config do
    it { should have_line /^service timestamps debug datetime.*$/ }
  end
  describe cisco_ios_running_config do
    it { should have_line /^service timestamps log datetime.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.6' }
end

control '5.2.7 Binding Logging Service to Loopback interface' do
  title 'Bind logging to the loopback interface'
  desc 'Logging messages are bound to the loopback interface'

  impact 1.0
  tag cis: '2.2.7'

  describe cisco_ios_running_config do
    it { should have_line /^logging source-interface.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.7' }
end

# -----------------------------------------------------------
# 5.3 NTP Rules
# -----------------------------------------------------------

control '5.3.1 Ensure trusted NTP server exists' do
  title 'Configure NTP to Authorized NTP server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.3.2'

  describe cisco_ios_running_config do
    it { should have_line /^ntp server.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.3.1' }
end

# -----------------------------------------------------------
# 5.4 Loopback Rules
# -----------------------------------------------------------

control '5.4.1 Require loopback interface' do
  title 'Define and configure one loopback interface'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.4.1'

  describe cisco_ios_file_output('show_ip_interface_brief', includes: 'Loopback') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.1' }
end

control '5.4.2 Require Binding AAA Service to an interface' do
  title 'Bind AAA services to the physical or logical interface'
  desc 'Authentication, authorization and accounting (AAA) services are bound to the Physical or logical interface'

  impact 1.0
  tag cis: '2.4.2'

  describe cisco_ios_running_config do
    it { should have_line /tacacs source.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.2' }
end

control '5.4.3 Require Binding the NTP Service to Loopback interface' do
  title 'Bind the NTP service to the loopback interface'
  desc 'The network time protocol (NTP) service is bound to the loopback interface'

  impact 1.0
  tag cis: '2.4.3'

  describe cisco_ios_running_config do
    it { should have_line /^ntp source.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.3' }
end

control '5.4.4 Require Binding TFTP Client Service to Management Interface' do
  title 'Require Binding TFTP Client Service to Management Interface'
  desc 'Bind the TFTP service to the Management interface. Not Applicable. Only SCP/SFTP secure protocol is used in the internal network'

  impact 1.0
  tag cis: '2.4.4'

  describe cisco_ios_running_config do
    it { should have_line /tftp source.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.4' }
end

# -----------------------------------------------------------
# 5.5 Control Plane Rules
# -----------------------------------------------------------

control '5.5.1 Control plane policing' do
  title 'Control plane policing'
  desc 'Configure control plan policy. The CPP feature protects the control plane of Cisco IOS Software-based routers against many attacks, including reconnaissance and denial-of-service (DoS) attacks. In this manner, the control plane can maintain packet forwarding and protocol state despite an attack or heavy load on the router'

  impact 1.0

  describe cisco_ios_file_output('show_policy_map_control_plane') do
    it { should have_line /Service-policy\s+input.*/ }
  end
  describe cisco_ios_file_output('show_ip_access_list') do
    it { should have_line /(COPP|cpp)/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.1' }
end

control '5.5.2 Control plane policing for RHO Packets' do
  title 'Control plane policing for RHO Packets'
  desc 'Configure control plan policy for IPv6. The CPP feature protects the untrusted IPv6 Type 0 Routing header packets to an IPv6-enabled device. Applicable for Internet facing ASR routers in ISP Compartment'

  impact 1.0

  describe cisco_ios_file_output('show_policy_map_control_plane') do
    its('stdout') { should match /Service-policy\s+input.*/ }
  end
  describe cisco_ios_file_output('show_ipv6_access_list') do
    its('stdout') { should match /DROP-IPv6-RHO/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.2' }
  only_if { ISP_COMPARTMENT == true }
end

# -----------------------------------------------------------
# 6.1 Routing Rules
# -----------------------------------------------------------

control '6.1.1 Forbid IP source-route' do
  title 'Forbid IP source-route'
  desc 'Disable source routing'

  impact 1.0
  tag cis: '3.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^no ip source-route$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.1' }
end

control '6.1.2 Forbid IP Proxy ARP' do
  title 'Forbid IP Proxy ARP'
  desc 'Disable proxy ARP on active interfaces'

  impact 1.0
  tag cis: '3.1.2'

  describe cisco_ios_interfaces.where { proxy_arp_enabled? } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.2' }
end

control '6.1.3 Forbid Tunnel Interfaces' do
  title 'Forbid Tunnel Interfaces'
  desc 'Do not define any tunnel interfaces'

  impact 1.0
  tag cis: '3.1.3'

  describe cisco_ios_file_output('show_ip_interface', includes: 'tunnel') do
    it { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.3' }
  only_if { ISP_COMPARTMENT == true }
  only_if { IGWC_COMPARTMENT == true }
end

control '6.1.4 Enable Unicast Reverse Path Forwarding (uRPF)' do
  title 'Enable Unicast Reverse Path Forwarding (uRPF)'
  desc 'Configure unicast reverse-path forwarding (uRPF) loose mode on all high risk interfaces. Only applicable on external or high risk interfaces. External or high risk interface refers to connectivity to internet or any public network'

  impact 1.0
  tag cis: '3.1.3'

  describe cisco_ios_interfaces.where { ip_verify_source != 'reachable-via rx' } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.4' }
end

# -----------------------------------------------------------
# 6.2 Border Routing Filtering
# -----------------------------------------------------------

control '6.2.1 Forbid Private Source Addresses from External Networks' do
  title 'Forbid Private Source Addresses from External Networks'
  desc 'The device is configured to restrict access fro traffic from external networks that have source address that should only appear from internal networks. To forbid the private IP addresses from public domain and to allow only the designated IP range to the firewall. Only applicable on the public facing (untrusted) interfaces of the ISP routers in the ISP Compartment'

  impact 1.0
  tag cis: '3.2.1'

  describe cisco_ios_file_output('show_ip_access_list') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.1' }
end

control '6.2.2 Set inbound access group on External inteface' do
  title 'Set inbound access group on External inteface'
  desc 'Set inbound access group on public interfaces'

  impact 1.0
  tag cis: '3.2.2'

  EXTERNAL_INTERFACES.each do |ext_interface|
    describe cisco_ios_running_config(section: "interface #{ext_interface}") do
      it { should have_line /ip\s+access-group\s+.*\s+in$/ }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.2' }
end


# -----------------------------------------------------------
# 6.3.1 Key Chain Configuration
# -----------------------------------------------------------

control '6.3.1.1 Establish the Key Chain' do
  title 'Establish the Key Chain'
  desc 'Set the key chain. Only applicable for MACsec with pre-shared key running routers (IGWC routers)'

  impact 1.0
  tag cis: '3.3.1.1'

  describe cisco_ios_running_config(section: 'key chain') do
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.1.1' }
  only_if { IGWC_COMPARTMENT == true }
end

control '6.3.1.2 Configure the Key Number' do
  title 'Configure the Key Number'
  desc 'Configure the key number. Only applicable for MACsec with pre-shared key running routers (IGWC routers)'

  impact 1.0
  tag cis: '3.3.1.2'

  describe cisco_ios_running_config(section: 'key chain') do
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.1.2' }
  only_if { IGWC_COMPARTMENT == true }
end

control '6.3.1.3 Configure the Key String' do
  title 'Configure the Key String'
  desc 'Configure the key string. Only applicable for MACsec with pre-shared key running routers (IGWC routers)'

  impact 1.0
  tag cis: '3.3.1.3'

  describe cisco_ios_running_config(section: 'key chain') do
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.1.3' }
  only_if { IGWC_COMPARTMENT == true }
end


# -----------------------------------------------------------
# 6.3.2 Require EIGRP Authentication if Protocol is Used
# -----------------------------------------------------------

control '6.3.2.1 Establish the EIGRP Address Family' do
  title 'Establish the EIGRP Address Family'
  desc 'Configure the EIGRP address family.'

  impact 0
  tag cis: '3.3.1.4'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_running_config(section: 'router eigrp') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.1' }
end

control '6.3.2.2 Establish the EIGRP Address Family default interface' do
  title 'Establish the EIGRP Address Family default interface'
  desc 'Configure the EIGRP default interface under address family.'

  impact 0
  tag cis: '3.3.1.5'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_running_config(section: 'router eigrp') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.2' }
end

control '6.3.2.3 Establish the EIGRP Address Family Key Chain' do
  title 'Establish the EIGRP Address Family Key Chain'
  desc 'Configure the EIGRP address family key chain.'

  impact 0
  tag cis: '3.3.1.6'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_running_config(section: 'router eigrp') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.3' }
end

control '6.3.2.4 Establish the EIGRP Address Family Authentication Mode' do
  title 'Establish the EIGRP Address Family Authentication Mode'
  desc 'Configure the EIGRP address family authentication mode.'

  impact 0
  tag cis: '3.3.1.7'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_running_config(section: 'router eigrp') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.4' }
end

control '6.3.2.5 Establish the interface with the EIGRP Key Chain' do
  title 'Establish the interface with the EIGRP Key Chain'
  desc 'Configure the interface with the EIGRP key chain.'

  impact 0
  tag cis: '3.3.1.8'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_file_output('show_ip_eigrp_int') do
      it { should_not be_empty }
    end
    describe cisco_ios_file_output("show_run_int_#{EIGRP_INTERFACE}", includes: 'key-chain') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.5' }
end

control '6.3.2.6 Establish the interface with the EIGRP Authentication Mode' do
  title 'Establish the interface with the EIGRP Authentication Mode'
  desc 'Configure the interface with the EIGRP Authentication Mode.'

  impact 0
  tag cis: '3.3.1.9'

  describe.one do
    describe 'EIGRP Protocol' do
      skip 'Not applicable. EIGRP Protocol is not implemented'
    end
    describe cisco_ios_file_output('show_ip_eigrp_int') do
      it { should_not be_empty }
    end
    describe cisco_ios_file_output("show_run_int_#{EIGRP_INTERFACE}", includes: 'authentication mode') do
      it { should_not be_empty }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2.6' }
end

# -----------------------------------------------------------
# 6.3.3 Key Chain Configuration
# -----------------------------------------------------------

control '6.3.3.1 Require the Message Digest for OSPF' do
  title 'Require the Message Digest for OSPF'
  desc 'Applicable only for OSPF Protocol running on ASR routers'

  impact 1.0
  tag cis: '3.3.2.1'

  describe cisco_ios_running_config(section: 'router ospf') do
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.3.1' }
end

control '6.3.3.2 Configure the interface for Message Digest Authentication' do
  title 'Configure the interface for Message Digest Authentication'
  desc 'Applicable only for OSPF Protocol running on ASR routers'

  impact 1.0
  tag cis: '3.3.2.1'

  describe cisco_ios_running_config(includes: "interface #{OSPF_INTERFACE}") do
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.3.2' }
end

# -----------------------------------------------------------
# 6.3.4 Require RIpv2 Authentication if Protocol is Used
# -----------------------------------------------------------

control '6.3.4.1 Configure the interace with the RIpv2 Key Chain' do
  title 'Configure the interace with the RIpv2 Key Chain'
  desc 'Configure the interace with the RIpv2 Key Chain.'

  impact 1.0
  tag cis: '3.3.3.4'

  describe.one do
    describe 'RIP Protocol' do
      skip 'Not applicable. RIP Protocol is not implemented'
    end
    describe cisco_ios_running_config(includes: "interface #{RIP_INTERFACE}") do
      it { should_not be_empty }
    end
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.4.1' }
end

control '6.3.4.2 Configure the interace with the RIpv2 Authentication Mode' do
  title 'Configure the interace with the RIpv2 Authentication Mode'
  desc 'Configure the interace with the RIpv2 Authentication Mode.'

  impact 1.0
  tag cis: '3.3.3.5'

  describe.one do
    describe 'RIP Protocol' do
      skip 'Not applicable. RIP Protocol is not implemented'
    end
    describe cisco_ios_running_config(section: 'key chain') do
      it { should_not be_empty }
    end
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.4.2' }
end

# -----------------------------------------------------------
# 6.3.5 Require BGP Authentication if Protocol is Used
# -----------------------------------------------------------

control '6.3.5.1 BGP Authentication' do
  title 'BGP Authentication'
  desc 'Configure BGP neighbor authentication where feasible.  Only for ASR in the ISP compartment'

  impact 1.0
  tag cis: '3.3.4.1'

  describe cisco_ios_running_config(section: 'router bgp') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.5.1' }
  only_if { ISP_COMPARTMENT == true }
end

# -----------------------------------------------------------
# 6.3.6 Hot Standby Router Protocol (HSRP)
# -----------------------------------------------------------

control '6.3.6.1 Configure Hot Standby Router Protocol (HSRP)' do
  title 'Configure Hot Standby Router Protocol (HSRP)'
  desc 'Configure HSRP on interface on both routers. Applicable only for ASR routers in the ISP Compartment.  Not applicable for ASR routers of the IGWC and DCI where the HSRP is not configured'

  impact 1.0

  describe cisco_ios_file_output('show_standby') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.6.1' }
  only_if { ISP_COMPARTMENT == true }
end

# -----------------------------------------------------------
# 6.3.7 IPv6 Configuration
# -----------------------------------------------------------

control '6.3.7.1 IPv6 Settings' do
  title 'IPv6 Settings'
  desc 'Disable the IPv6 Settings on all interfaces. IPv6 will be enabled on ASR routers in the ISP Compartment only'

  impact 1.0

  describe cisco_ios_running_config(includes: 'ipv6') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.5.1' }
  only_if { ISP_COMPARTMENT == true }
end

