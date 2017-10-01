# imapfilter
Python based imap filtering utility that doesn't force you to use regular expressions.


**Use at your own risk.  Not responsible for lost or stolen emails.**


## Configuration file location default
normal user:
	~/.imapfilter.conf
or for root:
	/etc/imapfilter.conf

Configuration file must have permissions set to 0600

## Process ID file default
	/tmp/imapfilter.py.$(USER)
