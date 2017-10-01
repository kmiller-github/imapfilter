#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""imapfilter

Daemon for manipulating emails in one or more imap accounts and folders.

Example:
    imapfilter -h for help
    See sample imapfilter.conf file for filtering rules.

Copyright:
    This file must be distributed with the LICENSE file containing the GPLv3.0 license.

Testing:
    Ubuntu 16.04: Python 2.7.12

TODO:
    More granular error checking for processConnections
    Make address searches aware of multiple addresses, ie cc,bcc
    Marking action
    Delete action? Or just continue to use move to trash?
    init.d style system daemon
    Multi-processing:
        Each connection?
    IDLE:
        How do we detect connection failures in idle?
        How do we handle connection failures if idle is being used?
        Stop processing messages until all accounts are viable or only process
        rules that are not associated with the failed connection?
    WHOIS: Experimental, issues with requests/second to some whois databases
"""

#   _________
#__/Imports  \____________________
import sys, os, stat, syslog, daemon, signal, inspect
import getpass, argparse, ConfigParser
import unicodedata, re
import email, email.utils, imaplib, pythonwhois
from time import sleep
from datetime import date, timedelta

#   ___________
#__/Authorship \__________________
__author__ = "K. Miller"
__copyright__ = "Copyright (c) September, 2017, K. Miller"
__credits__ = ["K. Miller"]
__license__ = "GPL version 3.0"
__version__ = "0.1"
__maintainer__ = "K. Miller"
__email__ = ""
#__status__ = "Production"
__status__ = "Development"

#   _________
#__/Classes  \____________________
class imapFilter():
    """Work engine for the imap connection, condition, and rule processing.
    """
    def __init__(self, config):
        """ Setup defaults, options connections, rules, and signal processing

        Args:
            config (ConfigParser): Preparsed configuration options
        """
        # Database dictionaries
        self.connections = {}
        self.conditions = {}
        self.rules = {}

        self.signalRaised = False
        self.pollTime = 60 # Default polling delay time in seconds

        # Whois
        self.whois = False
        self.registrars = {} # cache

        # Get everything setup up from the configuration file
        self.setupGeneral(config)
        self.setupConnections(config)
        self.setupConditions(config)
        self.setupRules(config)

        # Assign a signal handler to exit gracefully
        signal.signal(signal.SIGINT, self.signalHandler)
        signal.signal(signal.SIGTERM, self.signalHandler)

        return

    def setupGeneral(self, config):
        """ Process the general section of the configuration file

        Args:
            config (ConfigParser): Preparsed configuration options
        """
        if (config.has_option('general', 'whois') and config.get('general', 'whois') == 'enable'):
            self.whois = True

        # Enable logging
        if config.has_option('general', 'logging'):
            logMask = syslog.LOG_UPTO(eval(config.get('general', 'logging')))
        else:
            logMask = syslog.LOG_UPTO(syslog.LOG_EMERG)
        syslog.setlogmask(logMask)

        if config.has_option('general', 'polltime'):
            self.polltime = config.getint('general', 'polltime')

    def setupConnections(self, config):
        """ Process the account section of the configuration file

        Args:
            config (ConfigParser): Preparsed configuration options
        """
        accounts = config.items('accounts')
        for account in accounts:
            accountDetails = [x.strip() for x in account[1].split(':')]
            self.connections[account[0]] = [(accountDetails[0], accountDetails[1], accountDetails[2]), None]

    def setupConditions(self, config):
        """ Process the conditions section of the configuration file

        Args:
            config (ConfigParser): Preparsed configuration options
        """
        for condition in config.items('conditions'):
            field, test = condition[1].split(',', 1)
            funcName, param = test.split('(', 1)
            funcName = funcName.strip()
            param = param.rstrip().rstrip(')') # Allow whitespace in test string
            if funcName[0] == 'i':
                i = 1
            else:
                i = 0
            localFunc = getattr(self, funcName[i:]) # Crash on fail
            self.conditions[condition[0]] = (field, funcName[i:], param, i)
        return

    def parseRuleCond(self, ruleCond):
        """ Process the rule, replacing the conditional parts

        Args:
            ruleCond (str): Preprocessed rule-conidtional string.
        """
        for key, cond in self.conditions.items():
            ruleCond = ruleCond.replace(key, 'self.' + cond[1] +
                                        '(headers, ' + '\'' + cond[0] + '\',' +
                                        '\'' + cond[2] + '\',' + str(cond[3]) + ')')
        headers = {} # Empty test header to varify some functions.
        # This will exception if it runs any bad code.
        # Conditional short-curcuits will not be parsed.
        # Maybe find a way to parse the logic to test each conditional?
        eval(ruleCond)
        return ruleCond

    def setupRules(self, config):
        """ Process the rules section of the configuration file

        Args:
            config (ConfigParser): Preparsed configuration options
        """
        for rule in config.items('rules'):
            ruleParse = rule[1].replace('\n', ' ').split(',')

            ruleAccount = ruleParse[0].strip().lower()
            rulePrecedent = (int)(ruleParse[1].strip())
            ruleDirectory = ruleParse[2].strip()
            ruleSearch = ruleParse[3].strip()

            ruleCond = self.parseRuleCond(ruleParse[4].lower())

            thenAction, actionParameters = ruleParse[5].split('(')
            thenAction = thenAction.strip()
            thenActionAccount, thenActionDirectory = actionParameters.split(':')
            thenActionAccount = thenActionAccount.strip().lower()
            thenActionDirectory = thenActionDirectory.strip().rstrip(')').strip()

            if len(ruleParse) > 6:
                elseAction, actionParameters = ruleParse[6].split('(')
                elseAction = elseAction.strip()
                elseActionAccount, elseActionDirectory = actionParameters.split(':')
                elseActionAccount = elseActionAccount.strip().lower()
                elseActionDirectory = elseActionDirectory.strip().rstrip(')').strip()
            else:
                elseAction = ''
                elseActionAccount = ''
                elseActionDirectory = ''

            self.rules[rule[0]] = { 'account':ruleAccount,
                                    'precedent':rulePrecedent,
                                    'directory':ruleDirectory,
                                    'search':ruleSearch,
                                    'condition':ruleCond,
                                    'thenaction':thenAction,
                                    'thenaccount':thenActionAccount,
                                    'thendirectory':thenActionDirectory,
                                    'elseaction':elseAction,
                                    'elseaccount':elseActionAccount,
                                    'elsedirectory':elseActionDirectory }
        return

    def openConnections(self):
        """ Open all available connections
        """
        for key, account in self.connections.items():
            try:
                # Check for port option
                params = account[0][0].split(',')
                if len(params) > 1:
                    params[1] = (int)(params[1])
                connection = imaplib.IMAP4_SSL(*params)
                self.connections[key][1] = connection
                try:
                    connection.login(account[0][1], account[0][2])
                except:
                    e = sys.exc_info()
                    syslog.syslog(syslog.LOG_WARNING, 'Login failed ' + e[0][0] + ' ' + account[0][1] + ' ' + str(e))
                    self.connections[key][1] = 0

                try:
                    connection.select('INBOX') # default mail box
                except:
                    e = sys.exc_info()
                    syslog.syslog(syslog.LOG_WARNING,
                                  'Default mailbox select failed ' +
                                  account[0][0] + ' ' + account[0][1] +
                                  ' ' + str(e))
                    self.connections[key][1] = 0
            except:
                e = sys.exc_info()
                syslog.syslog(syslog.LOG_WARNING, 'Connection failed ' + account[0][0] + ' ' + str(e))
                self.connections[key][1] = 0
        return

    def processConnections(self):
        """ Run the rules against all the open connections
        """
        try:
            rules = self.rules
            for ruleKey, rule in sorted(rules.items(), key=lambda rules: rules[1]['precedent']):
                connection = self.connections[rule['account']][1]
                if connection:
                    connection.select(rule['directory'])
                    result, data = connection.uid('search', None, eval(rule['search']))
                    uidList = data[0].split()
                    for uid in uidList:
                        resp, header = connection.uid('fetch', uid, '(BODY.PEEK[HEADER])')
                        message = email.message_from_string(header[0][1])
                        headers = {}
                        for key, eachHeader in message.items():
                            eachHeader = eachHeader.replace('\"', ' \" ') # Fix header decode issue
                            decodedHeader = email.Header.decode_header(eachHeader)
                            multiPartHeader = ''
                            for dHeader in decodedHeader:
                                if dHeader[1] != None:
                                    encodedHeader = dHeader[0].decode(dHeader[1]).encode('utf-8')
                                else:
                                    encodedHeader = dHeader[0]
                                multiPartHeader += encodedHeader
                            headers[key.lower()] = multiPartHeader
                        domain = '.'.join(headers['from'].split("@")[1].split(".")[-2:]).strip().rstrip('>')
                        if self.whois:
                            registrar = self.registrars.get(domain)
                            print '(', domain, ')', registrar
                            if registrar == None:
                                registrar = pythonwhois.get_whois(domain).get('registrar')
                                self.registrars[domain] = registrar # Probably limit the size of this?
                                print '(', domain, ')', registrar

                        # Apply rule to the message
                        if eval(rule['condition']): # rule's condition TRUE?
                            eval('self.' + rule['thenaction'] + '(' +
                                 'connection' + ',' + 'uid' + ',' + '\'' +
                                 rule['thenaccount'] + '\'' + ',' + '\'' + rule['thendirectory'] + '\'' + ')')
                        else:
                            if rule['elseaction'] != '':
                                eval('self.' + rule['elseaction'] + '(' +
                                     'connection' + ',' + 'uid' + ',' + '\'' +
                                     rule['elseaccount'] + '\'' + ',' + '\'' + rule['elsedirectory'] + '\'' + ')')
        except:
            e = sys.exc_info()
            syslog.syslog(syslog.LOG_WARNING, 'Processing failure ' + rule['account'] + ' ' + str(e))
        finally:
            for acctName, acct in self.connections.items():
                connection = acct[1]
                if connection:
                    connection.close()
                    connection.logout()
        return

    def contains(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for a substring

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        if nocase:
            header = header.lower()
            test = test.lower()
        return header.find(test) >= 0

    def matches(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for an exact match

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        if nocase:
            header = header.lower()
            test = test.lower()
        return header == test

    def beginswith(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for a specific prefix

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        if nocase:
            header = header.lower()
            test = test.lower()
        return header.startswith(test)

    def endswith(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for a specific postfix

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        if nocase:
            header = header.lower()
            test = test.lower()
        return header.endsswith(test)

    def addresscontains(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for an address with substring

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        addr = email.utils.parseaddr(header)[1]
        if nocase:
            addr = addr.lower()
            test = test.lower()
        return addr.find(test) >= 0

    def addressmatches(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for an address with an exact match

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        addr = email.utils.parseaddr(header)[1]
        if nocase:
            addr = addr.lower()
            test = test.lower()
        return addr == test

    def addressbeginswith(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for an address with a specific prefix

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        addr = email.utils.parseaddr(header)[1]
        if nocase:
            addr = addr.lower()
            test = test.lower()
        return addr.startswith(test)

    def addressendswith(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for an address with a specific postfix

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        addr = email.utils.parseaddr(header)[1]
        if nocase:
            addr = addr.lower()
            test = test.lower()
        return addr.endswith(test)

    def regexp(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header for a regular expression match

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        if nocase:
            ignore = re.IGNORECASE
        else:
            ignore = 0
        return re.search(test, header, ignore) != None

    def addressregexp(self, headers, field, test, nocase):
        """Conditional rule to test a specific email header address for a regular expression match

        Args:
            headers (dict): Parsed email headers
            field (str): email header ID (ie from,to,cc)
            test (str): string to test for in header
            nocase (bool): Case insensitive
        """
        header = headers.get(field.lower()) or ''
        addr = email.utils.parseaddr(header)[1]
        if nocase:
            ignore = re.IGNORECASE
        else:
            ignore = 0
        return re.search(test, addr, ignore) != None

    def moveto(self, From, uid, toAcct, directory):
        """Action to move an email from one directory to another

        Args:
            From (imaplib.IMAP4_SSL): Connection to account
            uid (int): message ID
            toAcct (str): Account name for email destination
            directory (str): Name of directory to copy email
        """
        syslog.syslog(syslog.LOG_INFO, 'Action: ' + inspect.stack()[0][3] +
                      ' from ' + ' ' + str(uid) +
                      ' to ' + ' ' + toAcct + ' ' + directory)

        # Is the 'to' account available?
        try:
            To = self.connections[toAcct][1]
        except:
            return False

        # Same account?
        if From == To:
            try:
                resp, data = From.uid('copy', uid, directory)
            except:
                e = sys.exc_info()
                syslog.syslog(syslog.LOG_ERR, 'Action: ' + inspect.stack()[0][3] +
                              ' message ' + ' ' + str(uid) +
                              ' to ' + ' ' + toAcct + ' ' + directory)
                syslog.syslog(syslog.LOG_ERR, 'Message copy failed' + e[0][0] + ' ' + str(e))
                return False
        else:
            try:
                resp, data = From.uid('fetch', uid, '(FLAGS INTERNALDATE BODY.PEEK[])')
            except:
                return False
            if resp == 'OK':
                mesg = data[0][1]
                #flags = imaplib.ParseFlags(data[0][0])
                #flag_str = " ".join(flags)
                flag_str = ''
                date = imaplib.Time2Internaldate(imaplib.Internaldate2tuple(data[0][0]))
                try:
                    resp, data = To.append(directory, flag_str, date, mesg)
                except:
                    return False
            else:
                return False

        # Mark for deletion
        if resp == 'OK':
            try:
                resp, data = From.uid('store', uid, '+FLAGS', '(\Deleted)')
            except:
                return False
            return True
        return False

    def copyto(self, From, uid, toAcct, directory):
        """Action to copy an email from one directory to another

        Args:
            From (imaplib.IMAP4_SSL): Connection to account
            uid (int): message ID
            toAcct (str): Account name for email destination
            directory (str): Name of directory to copy email
        """
        syslog.syslog(syslog.LOG_INFO, 'Action: ' + inspect.stack()[0][3] +
                      ' message ' + ' ' + str(uid) +
                      ' to ' + ' ' + toAcct + ' ' + directory)

        # Is the 'to' account available?
        try:
            To = self.connections[toAcct][1]
        except:
            return False

        # Same account?
        if From == To:
            try:
                resp, data = From.uid('copy', uid, directory)
            except:
                e = sys.exc_info()
                syslog.syslog(syslog.LOG_ERR, 'Action: ' + inspect.stack()[0][3] +
                              ' from ' + ' ' + str(uid) +
                              ' to ' + ' ' + toAcct + ' ' + directory)
                syslog.syslog(syslog.LOG_ERR, 'Message copy failed' + e[0][0] + ' ' + str(e))
                return False
        else:
            try:
                resp, data = From.uid('fetch', uid, '(FLAGS INTERNALDATE BODY.PEEK[])')
            except:
                return False
            if resp == 'OK':
                mesg = data[0][1]
                #flags = imaplib.ParseFlags(data[0][0])
                #flag_str = " ".join(flags)
                flag_str = ''
                date = imaplib.Time2Internaldate(imaplib.Internaldate2tuple(data[0][0]))
                try:
                    resp, data = To.append(directory, flag_str, date, mesg)
                except:
                    return False
            else:
                return False

    def signalHandler(self, signum, frame):
        """ Capture signals and set the raised flag
        """
        self.signalRaised = True
        return

    def mainLoop(self, once):
        """ Loop over connections until signal received
        """
        while not self.signalRaised:
            self.openConnections()
            self.processConnections()
            if self.signalRaised:
                continue
            if not once:
                sleep(self.pollTime)
            else:
                syslog.syslog(syslog.LOG_INFO, 'Ran once')
                self.signalRaised = True

#   _________
#__/Global   \____________________
def argParser():
    """ Return the parsed command line. """
    parser = argparse.ArgumentParser(
        description='Daemon for manipulating emails in one or more imap accounts and folders.')

    parser.add_argument(
        '-c', '--configfile', type=str, help='Configuration file', required=False)
    parser.add_argument(
        '-d', '--daemon', action="store_true", help='Put imapfilter into daemon mode', default=False)
    parser.add_argument(
        '-p', '--pidfile', type=str, help='Daemon mode Process ID file', default=False)
    parser.add_argument(
        '-1', '--once', action="store_true", help='Just run once', default=False)

    return parser.parse_args()

#   _________
#__/Main     \____________________
if __name__ == '__main__':

    # Add PID to syslogs
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_MAIL)

    commandLineOptions = argParser()

    # Setup the configuration file
    if commandLineOptions.configfile:
        configFile = commandLineOptions.configfile
    else:
        if getpass.getuser() == 'root':
            configFile = '/etc/imapfilter.conf'
        else:
            configFile = '~/.imapfilter.conf'
    configFile = os.path.expanduser(configFile)
    if (os.stat(configFile).st_mode & 0777) != (stat.S_IRUSR + stat.S_IWUSR):
        syslog.syslog(syslog.LOG_ERR, 'Config file ' + configFile + ' does not have it\'s permissions set to ' + str(oct(stat.S_IRUSR + stat.S_IWUSR)))
        print 'Config file ' + configFile + ' does not have it\'s permissions set to ' + str(oct(stat.S_IRUSR + stat.S_IWUSR))
        sys.exit(1)
    config = ConfigParser.ConfigParser()
    config.read([configFile])

    # Initialize email filtering from the configuration file
    emailFilter = imapFilter(config)

    # Do we turn the service into a daemon?
    if commandLineOptions.daemon:
        if commandLineOptions.pidfile:
            pidFile = commandLineOptions.pidfile
        else:
            pidFile = '/tmp/' + __file__ + '.' + getpass.getuser()

        daemon.daemonize(pidFile)
        syslog.syslog(syslog.LOG_INFO, 'Daemonized ' + __file__)

    # Start the work engine
    syslog.syslog(syslog.LOG_INFO, 'Starting ' + __file__)
    emailFilter.mainLoop(commandLineOptions.once)
    syslog.syslog(syslog.LOG_INFO, 'Shutting down imapfilter')

    sys.exit(0)

