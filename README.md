# imapfilter
Python based imap filtering utility that doesn't force you to use regular expressions.


**Use at your own risk.  Not responsible for lost or stolen emails.**


##configuration file location default
normal user:
	~/.imapfilter.conf
or for root:
	/etc/imapfilter.conf

Configuration file must have permissions set to 0600

##process ID file default
	/tmp/imapfilter.py.$(USER)
