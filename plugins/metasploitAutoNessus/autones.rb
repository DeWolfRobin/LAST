##
# This file is part of the Metasploit Framework and may be subject to           >---- licensing agreement, keep standard
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class MetasploitModule < Msf::Auxiliary

def initialize
    super(
          'Name' => 'AutoNes',
          'Version' => '$Revision: 1 $',
          'Description' => 'An automated nessus scan starter.',
          'Author' => 'Robin De Wolf',
          'License' => MSF_LICENSE 
)

    deregister_options('RPORT', 'RHOST')
end


def run_host(ip)

begin
puts "I HAZ SQL!!!!"
end >--- close
end >---- close
end >---- close
