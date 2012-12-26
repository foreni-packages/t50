#
# Regular cron jobs for the t50 package
#
0 4	* * *	root	[ -x /usr/bin/t50_maintenance ] && /usr/bin/t50_maintenance
