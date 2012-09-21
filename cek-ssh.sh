#!/usr/bin/env bash
# Mahyuddin Suasnto <udienz@rad.net.id>

BASE=$HOME/project/ssh-checker
LOG=$BASE/log
SENDEMAIL=0

if [ -f /etc/debian_version ]; then
        AUTHLOG=/var/log/auth.log
    elif [ -f /etc/redhat-release]; then
        AUTHLOG=/var/log/secure
    fi

echo "LOG at $AUTHLOG"

send_mail () {
	ipaddr=$1
        echo "Getting email addresses"
        ipreverse=$(echo $ipaddr | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
        email=$(host -t any $ipreverse.abuse-contacts.abusix.org | awk {'print$4'} | sed -e 's/"//g' | head -n1 )

        echo "Getting logs"
        sudo fgrep "$ipaddr" $AUTHLOG* | sudo grep "localhost sshd" > $LOG/$ipaddr.log
                echo "Sending email"
                cat > $LOG/$ipaddr.mail << EOF
Dear Abuse Team ($email),

Our server has has received roughly $count attempts to login via the SSH protocol 
from your host at $ipaddr.  I have attached the relevant portions of my logfiles.

The recipient address of this report was provided by the Abuse Contact Database
of abusix.org. If you have any question or think the recipient address
might be wrong, contact abusix.org directly via email (info@abusix.org). Further
information about the Abuse Contact Database can be found here:

http://abusix.org/services/abuse-contact-db

abusix.org is neither responsible nor liable for
the content or accuracy of this message.

Thank you for your understanding.
Mahyuddin Susanto
EOF

        if grep "^$ipaddr\$" /etc/apf/deny_hosts.rules ; then
                echo "Already in blocked list"
        else
                echo "Adding $ipaddr to blocked list"
                sudo /usr/local/sbin/apf --deny $host \"brute force sebanyak $count \"
        fi
	
#	if [ SENDEMAIL == 1    
#        mutt -a $LOG/$ipaddr.log -c hostmaster@sby.rad.net.id,fail2ban@blocklist.de -s "[Fail2Ban] ssh: banned $ipaddr" -- $email < $LOG/$ipaddr.mail
        mutt -a $LOG/$ipaddr.log -s "[Fail2Ban] ssh: banned $ipaddr" -- $email < $LOG/$ipaddr.mail
}

# Fill in your own whitelisted hosts here
whitelist="202.154.57.15 202.154.4. `host home.example.com | sed -e 's/[^0-9]*//'`"

sudo sed -e '/sshd\[[0-9]*\]: Failed password/!d' \
        -e 's/.*Failed password for.*from //' \
        -e 's/ port.*//' $AUTHLOG | sort | uniq -c | \
while read info
do
	set -- $info
	count=$1
	host=$2
	whitelisted=0

	host=$(echo $host | sed -e 's/::ffff://')
	number_of_usernames=$(sudo sed -e '/sshd\[[0-9]*\]: Failed password.*from '$host'/!d' \
		-e 's/.*Failed password for //' -e 's/ from .*//' \
		$AUTHLOG  | sort -u | wc -l)

	for white in $whitelist ; do
        	if [ "$white" = "$host" ] ; then
               	whitelisted=1
        	fi
	done

	if [ "$whitelisted" = "1" ] ; then
        	echo "$count attempts from WHITELISTED $host"
		elif sudo grep -q "$host" /etc/apf/deny_hosts.rules ; then
        	: #echo "$host is blacklisted"
		else
        	#echo "$count attempts from $host"
       		#host $host
        if [ "$count" -gt "10" -o "$number_of_usernames" -gt "4" ] ; then
                touch $LOG/$host.mail $LOG/$host.log
                send_mail $host
                echo "$host broute force $count. need to block"
                #sudo /usr/local/sbin/apf --deny $host \"brute force sebanyak $count \"
        else
        :       #echo "WARNING: $host is not blacklisted"
        fi
fi
done
