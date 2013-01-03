#!/usr/bin/ruby
#Description:Script for DNS Recon
#Author: Carlos Perez carlos_perez[at]darkoperator.com
require 'getoptlong'
require 'rubygems'
require 'Net/DNS'
#http://rubyforge.org/projects/pnet-dns/
require 'ip'
#http://rubyforge.org/projects/ip-address/
trap "SIGINT", 'exit'

def axfr(target, nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	query = res.query(target, "NS")
	if (query)
		(query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |nsrcd|
			res.nameservers=(nsrcd.nsdname)
			zone = res.axfr(target)
			if zone.length > 0
				puts "Zone Transfer Succesfull on Nameserver #{res.nameserver} \n\n"
				zone.each do |rr| puts rr.inspect
				end
			else
				puts "Zone transfer failed for #{nsrcd.nsdname}"
			end
	  
		end
	end
end

#-------------------------------------------------------------------------------
def dnsbrute(target, wordlist, nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	arr = []
	i, a = 0, []
	begin
		arr = IO.readlines(wordlist)
	rescue
		puts "Could not open file"
	end
	arr.each do |line|
		if i < 10
			a.push(Thread.new {
					begin
						query1 = res.search("#{line.chomp}.#{target}")
						if (query1)
							query1.answer.each do |rr|
								if rr.class == Net::DNS::RR::A
									print "#{line.chomp}.#{target},#{rr.address}\n"
									next unless rr.class == Net::DNS::RR::CNAME
								end
							end
						end
					end
				})
			i += 1
		else
			sleep(0.01) and a.delete_if {|x| not x.alive?} while not a.empty?
			i = 0
		end
	end
	a.delete_if {|x| not x.alive?} while not a.empty?
end

#-------------------------------------------------------------------------------
def tldexpnd(target,nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	i, a = 0, []
	tlds = [
		"com", "org", "net", "edu", "mil", "gov", "uk", "af", "al", "dz",
		"as", "ad", "ao", "ai", "aq", "ag", "ar", "am", "aw", "ac","au",
		"at", "az", "bs", "bh", "bd", "bb", "by", "be", "bz", "bj", "bm",
		"bt", "bo", "ba", "bw", "bv", "br", "io", "bn", "bg", "bf", "bi",
		"kh", "cm", "ca", "cv", "ky", "cf", "td", "cl", "cn", "cx", "cc",
		"co", "km", "cd", "cg", "ck", "cr", "ci", "hr",	"cu", "cy", "cz",
		"dk", "dj", "dm", "do", "tp", "ec", "eg", "sv", "gq", "er", "ee",
		"et", "fk", "fo", "fj",	"fi", "fr", "gf", "pf", "tf", "ga", "gm",
		"ge", "de", "gh", "gi", "gr", "gl", "gd", "gp", "gu", "gt", "gg",
		"gn", "gw", "gy", "ht", "hm", "va", "hn", "hk", "hu", "is", "in",
		"id", "ir", "iq", "ie", "im", "il", "it", "jm", "jp", "je", "jo",
		"kz", "ke", "ki", "kp", "kr", "kw", "kg", "la", "lv", "lb", "ls",
		"lr", "ly", "li", "lt", "lu", "mo", "mk", "mg", "mw", "my", "mv",
		"ml", "mt", "mh", "mq", "mr", "mu", "yt", "mx", "fm", "md", "mc",
		"mn", "ms", "ma", "mz", "mm", "na", "nr", "np", "nl", "an", "nc",
		"nz", "ni", "ne", "ng", "nu", "nf", "mp", "no", "om", "pk", "pw",
		"pa", "pg", "py", "pe", "ph", "pn", "pl", "pt", "pr", "qa", "re",
		"ro", "ru", "rw", "kn", "lc", "vc", "ws", "sm", "st", "sa", "sn",
		"sc", "sl", "sg", "sk", "si", "sb", "so", "za", "gz", "es", "lk",
		"sh", "pm", "sd", "sr", "sj", "sz", "se", "ch", "sy", "tw", "tj",
		"tz", "th", "tg", "tk", "to", "tt", "tn", "tr", "tm", "tc", "tv",
		"ug", "ua", "ae", "gb", "us", "um", "uy", "uz", "vu", "ve", "vn",
		"vg", "vi", "wf", "eh", "ye", "yu", "za", "zr", "zm", "zw", "int",
		"gs", "info", "biz", "su", "name", "coop", "aero" ]
      
	begin
		tlds.each do |tld|
			if i < 10
				a.push(Thread.new {
						begin
							query1 = res.search("#{target}.#{tld}")
							if (query1)
								query1.answer.each do |rr|
									puts "#{target}.#{tld},#{rr.address},A \n"
								end
			
							end
						end
					})
				i += 1
			else
				sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
				i = 0
			end
		end
		a.delete_if {|x| not x.alive?} while not a.empty?
	end
end
    
#-------------------------------------------------------------------------------
def genrcd(target,nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	query = res.search(target)

	if (query)
		query.answer.each do |rr|
			next unless rr.class == Net::DNS::RR::A
			puts "#{target},#{rr.address},A "
		end
	else
		print "query failed: " + res.errorstring + "\n"
	end
  
	query = res.query(target, "SOA")

	if (query)
		(query.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
			query1 = res.search(rr.mname)
			if (query1)
				query1.answer.each do |ip|
					puts 'CNAME' if ip.type == 'CNAME'
					puts "#{rr.mname},#{ip.address},SOA"
				end
			end
		end
	else
		print "query failed: " + res.errorstring + "\n"
	end
	query = res.query(target, "NS")
	if (query)
		(query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |rr|
			query1 = res.search(rr.nsdname)
			if (query1)
				query1.answer.each do |ip|
					next unless ip.class == Net::DNS::RR::A
					puts "#{rr.nsdname},#{ip.address},NS"
				end
			end
		end
	else
		print "query failed: " + res.errorstring + "\n"
	end
	query = res.query(target, "MX")
	if (query)
		(query.answer.select { |i| i.class == Net::DNS::RR::MX}).each do |rr|
			query1 = res.search(rr.exchange)
			if (query1)
				query1.answer.each do |ip|
					puts "#{rr.exchange},#{ip.address},MX,#{rr.preference}"
				end
			end
		end
	else
		print "query failed: " + res.errorstring + "\n"
	end
end

#-------------------------------------------------------------------------------
def reverselkp(ip1,ip2,nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	i, a = 0, []
	puts "Reverse Lookup for IP Renge from #{ip1} to #{ip2}"
	IP::Range[ip1, ip2].each do |ip|
		query = res.query(ip.ip_address)
		query.each_ptr do |addresstp|
			if i < 10
				a.push(Thread.new {
						puts "#{addresstp},#{ip.ip_address}"
					})
    
				i += 1
			else
				sleep(0.10) and a.delete_if {|x| not x.alive?} while not a.empty?
				i = 0
			end
		end
		a.delete_if {|x| not x.alive?} while not a.empty?
	end
end
#-------------------------------------------------------------------------------
def srvqry(dom,nssrv)
	res = Net::DNS::Resolver.new
	if nssrv.nil?
	else
		res.nameserver = (nssrv)
	end
	srvrcd = [
		"_gc._tcp.","_kerberos._tcp.", "_kerberos._udp.","_ldap._tcp","_test._tcp.",
		"_sips._tcp.","_sip._udp.","_sip._tcp.","_aix._tcp.","_aix._tcp.","_finger._tcp.",
		"_ftp._tcp.","_http._tcp.","_nntp._tcp.","_telnet._tcp.","_whois._tcp.","_h323cs._tcp.",
		"_h323cs._udp.","_h323be._tcp.","_h323be._udp.","_h323ls._tcp.","_h323ls._udp."]
  
	srvrcd.each do |a|
		trg = "#{a}#{dom}"
		query = res.query(trg , "SRV")
		if (query)
			(query.answer.select { |i| i.class == Net::DNS::RR::SRV}).each do |rr|
				if (rr.target =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
					puts "#{trg},#{rr.target},#{rr.port}"
				else
					srvip = res.search(rr.target)
					srvip.answer.each do |ip|
  
						puts "#{trg},#{ip.address},#{rr.port}" if ip.type != "CNAME"
					end
				end
			end
		end
	end
end

#-------------------------------------------------------------------------------
def usage
	puts "\n\Dnsrecon 1.6\n"
	puts "By Carlos Perez \nEmail: carlos_perez[at]darkoperator.com\n\n"
	puts "This is a simple tool writen for target enumeration during authorized penetration test"
	puts "engaments. This tool provides diferent methods for enumerating targets thru DNS service."
	print( "
-t, --type  	
		Select the type of enumeration to be done.
		std  	Query for SOA, NS and MX Record of a target domain.
		tld  	Top Level Domain enumeration of a target domain.
		axf  	Perform a Zone transfer against all NS server Records
			of a target domain.
		rvs	Reverse Record Lookup enumeration against a targeted
			IP range.
		srv	Service Record Enumeration of VOIP, Active Directory and
			Network Services service records.
		brt	Bruteforce subdomain and host records using a wordlist.

-d, --target
		Domain to be targeted for enumeration.

-i, --ip
		Starting IP and end IP for a range to be used for reverse lookup 
		enumeration of a targeted domain. Exmpl. 192.168.1.1,192.168.1.253

-w, --wordlist
		Wordlist to be use for brutforce enumeration of host names and subdomains.

-s, --dns
		Alternate DNS server to use.
-h, --help
		This help message.
"
	)
end
#Main
#-------------------------------------------------------------------------------

type = nil
ip1 = nil
ip2 = nil
dnssrv = nil
wordlist = nil
trgtdom = nil
opts = GetoptLong.new(
      	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
      	[ '--type', '-t', GetoptLong::REQUIRED_ARGUMENT ],
      	[ '--ip','-i', GetoptLong::OPTIONAL_ARGUMENT ],
    	[ '--dns','-s', GetoptLong::OPTIONAL_ARGUMENT ],
      	[ '--wordlist','-w', GetoptLong::OPTIONAL_ARGUMENT ],
	[ '--target','-d', GetoptLong::OPTIONAL_ARGUMENT ]
    )
opts.each do |opt, arg|
	case opt
        	when '--help'
			usage()
        	when '--type'
			type = arg
        	when '--ip'
			ip1,ip2 =  arg.split(",")
		when '--dns'
			dnssrv = arg
		when '--wordlist'
			if File.exist?(arg)
	  			wordlist = arg
			else
				puts "File #{arg} does not exist."
				exit 0
			end
		when '--target'
			trgtdom = arg
      	end
end
if type != nil
	case type 
	when 'axfr'
		if trgtdom != nil
			axfr(trgtdom, dnssrv)
		else
			puts "For this type you must provide a target domain!"
			exit 0
		end
	when 'std'
		if trgtdom != nil
			genrcd(trgtdom, dnssrv)
		else
			puts "For this type you must provide a target domain!"
			exit 0
		end
	when 'brt'
		if trgtdom != nil
			dnsbrute(trgtdom, wordlist, dnssrv)
		else
			puts "For this type you must provide a target domain!"
			exit 0
		end
	when 'srv'
		if trgtdom != nil
			srvqry(trgtdom, dnssrv)
		else
			puts "For this type you must provide a target domain!"
			exit 0
		end
	when 'tld'
		if trgtdom != nil
			tldexpnd(trgtdom, dnssrv)
		else
			puts "For this type you must provide a target domain!"
			exit 0
		end
	when 'rvs'
		reverselkp(ip1,ip2,dnssrv)
	end
else
	usage()
end


