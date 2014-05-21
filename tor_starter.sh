#!/bin/bash 

#LOG='/tmp/atc_tor_starter.log'

while read -n1 line; do
	if [[ "$line" == '0' ]]; then
	### 0 == STOP
		echo "$(date '+%D %H:%M:%S'): *** request recv'd: stop tor ***"
		echo "$(date '+%D %H:%M:%S'): *** attempting stop ***"
		OUTPUT="$( service tor stop 2>&1 )"
		if [ $? -ne 0 ]; then
			echo "$OUTPUT"
			exit 1
		elif echo "$OUTPUT" | grep '\.\.\.fail[.!]' >/dev/null || \
		 ! echo "$OUTPUT" | grep '\.\.\.done[.!]' >/dev/null; then
			echo "$OUTPUT"
			if service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
				kill $( pgrep -x -d' ' tor )
			fi
		fi
		if service tor status 2>&1 | grep 'tor is not running' >/dev/null; then
			echo "OK"
		fi
	elif [[ "$line" == '1' ]]; then
	### 1 == START
		echo "$(date '+%D %H:%M:%S'): *** request recv'd: start tor ***"
		echo "$(date '+%D %H:%M:%S'): *** attempting start ***"
		OUTPUT="$( service tor start 2>&1 )"
		if [ $? -ne 0 ]; then
			echo "$OUTPUT"
			exit 1
		elif echo "$OUTPUT" | grep '\.\.\.fail[!.]' >/dev/null || \
		 ! echo "$OUTPUT" | grep '\.\.\.done[!.]' >/dev/null; then
			echo "$OUTPUT"
			if ! service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
				kill $( pgrep -x -d' ' tor )
				sleep 1
				OUTPUT="$( service tor start 2>&1 )"
				sleep 1
				if ! service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
					echo "$OUTPUT"
					exit 1
				else
					echo "$OUTPUT"
				fi
			fi
		fi
		if service tor status 2>&1 | grep 'tor is running' >/dev/null; then
			echo "OK"
		fi

	elif [[ "$line" == '2' ]]; then
	### 2 == RESTART
		echo "$(date '+%D %H:%M:%S'): *** request recv'd: restart tor ***"
		echo "$(date '+%D %H:%M:%S'): *** attempting restart ***"
		OUTPUT="$( service tor restart 2>&1 )"
		if [ $? -ne 0 ] || echo "$OUTPUT" | grep '\.\.\.fail[!.]' >/dev/null || \
		 ! echo "$OUTPUT" | grep '\.\.\.done[!.]' >/dev/null; then
			echo "$OUTPUT"

		### Restart didn't work! try stop, then start...
		###   first starting...
			tmpret=
			echo "$(date '+%D %H:%M:%S'): *** attempting stop ***"
			OUTPUT="$( service tor stop 2>&1 )"
			if [ $? -ne 0 ]; then
				echo "$OUTPUT"
				exit 1
			elif echo "$OUTPUT" | grep '\.\.\.fail[!.]' >/dev/null || \
			 ! echo "$OUTPUT" | grep '\.\.\.done[!.]' >/dev/null; then
				echo "$OUTPUT"
				if service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
					kill $( pgrep -x -d' ' tor )
				fi
			fi
			if service tor status 2>&1 | grep 'tor is not running' >dev/null ; then
				tmpret=1
			fi
		###   now starting....
			echo "$(date '+%D %H:%M:%S'): *** attempting start ***"
			OUTPUT="$( service tor start 2>&1 )"
			if [ $? -ne 0 ]; then
				echo "$OUTPUT"
				exit 1
			elif echo "$OUTPUT" | grep '\[fail\]' >/dev/null || \
			 ! echo "$OUTPUT" | grep '\[ *[oO][kK] *\]' >/dev/null; then
				echo "$OUTPUT"
				if ! service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
					kill $( pgrep -x -d' ' tor )
					sleep 1
					OUTPUT="$( service tor start 2>&1 )"
					sleep 1
					if ! service tor status 2>&1 | grep 'tor is running' >/dev/null ; then
						echo "$OUTPUT"
						exit 1
					fi
				fi
			fi
			if [ ! -z "$tmpret" ] && service tor status | grep 'tor is running' >/dev/null; then
				echo "OK"
			fi
		else
			echo "OK"
		fi
		
	else
		echo "$(date '+%D %H:%M:%S'): *** shutting down *** (key:$line)"
		exit
	fi
done
