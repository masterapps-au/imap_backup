#!/usr/bin/env python

"""
imap_backup
(c) 2021 Ryan Butterfield of Master Apps (https://github.com/masterapps-au)
Freely distributable under the terms of the MIT license.
"""

from __future__ import absolute_import, unicode_literals

import hashlib
import imaplib
from io import BytesIO
import itertools
import json
import logging
import mailbox
import multiprocessing
import os.path
import Queue
import re
import rfc822
import socket
import sys
import time
import traceback
import urllib2
from urlparse import parse_qs, urlparse
import uuid


SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
UID_RE = re.compile(br'UID (\d+)')
SPACE_RE = re.compile(br'\s+', re.MULTILINE)
MESSAGE_ID_RE = re.compile(br"^Message\-ID\: (.+)", re.IGNORECASE + re.MULTILINE)
IMAPBACKUP_DOMAIN = b'imap_backup.py.local'
LIST_RE = re.compile(br'^\(.*?\) \"(.+?)\" (.+)$')
FILENAME_RE = re.compile(r'[^a-zA-Z0-9\.\_\- ]')
ALL_MAILBOXES = '*'
X_MOZILLA_STATUS_READ = b'X-Mozilla-Status: 0001\n'
X_MOZILLA_STATUS_DELETED = b'X-Mozilla-Status: 0009\n'


logging.basicConfig(level=logging.INFO, 
    format='%(asctime)s %(levelname)s %(processName)s %(message)s',
    datefmt='%H:%M:%S')
logger = logging.getLogger()


#
# Utilities
#
def grouper(n, iterable):
    """
    Groups an iterable into iterable chunks of n.
    Taken from https://stackoverflow.com/questions/8991506/iterate-an-iterator-by-chunks-of-n-in-python
    """
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


#
# IMAP connection wrapper
#
class IMAPConnection(object):
    """
    Wraps an imaplib connection and allows for handling dropped connections and throttling.
    """
    def __init__(self, config, oauth_tokens, account):
        self.config = config
        self.oauth_tokens = oauth_tokens
        self.account = account
        self.mailbox_name = None
        self.imap = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
    
    def connect(self):
        """
        Connects to the mail account.
        """
        # set the socket timeout before connecting to the IMAP server
        socket.setdefaulttimeout(self.config.get('timeout', 120))
        
        # shut down any existing connections
        self.shutdown()
        
        # connect to the IMAP server for this account
        logger.info('%s/%s: Connecting to server (%s)...' % (
            self.account['email'], self.mailbox_name or ALL_MAILBOXES, self.account['host']))
        
        try:
            if self.account.get('ssl', True):
                self.imap = imaplib.IMAP4_SSL(self.account['host'], 
                    port=self.account.get('port', imaplib.IMAP4_SSL_PORT),
                    keyfile=self.account.get('keyfile'), 
                    certfile=self.account.get('certfile'))
            else:
                self.imap = imaplib.IMAP4(self.account['host'], 
                    port=self.account.get('port', imaplib.IMAP4_PORT))
            
            if self.account.get('oauth2'):
                oauth2_string = b'user=%s\1auth=Bearer %s\1\1' % (
                    str(self.account.get('username', self.account['email'])), 
                    str(self.oauth_tokens[self.account['oauth2']]))
                self.call(lambda imap: imap.authenticate('XOAUTH2', lambda x: oauth2_string), 
                    reconnect=False)
            else:
                self.call(lambda imap: imap.login(self.account.get('username', self.account['email']), 
                    self.account['password']), reconnect=False)
            
        except Exception as e:
            logger.error('%s/%s: Failed to connect to server: %s' % (
                self.account['email'], self.mailbox_name or ALL_MAILBOXES, e))
            self.shutdown()
            raise
        
        # if we'd previously selected a mailbox, then re-select it
        # this happens during re-connections
        if self.mailbox_name is not None:
            try:
                self.select_mailbox(self.mailbox_name, reconnect=False)
            except Exception:
                self.shutdown()
                raise
    
    def shutdown(self):
        """
        Shuts down the mail account connection.
        """
        if self.imap is not None:
            logger.info('%s/%s: Disconnecting from server (%s)...' % (
                self.account['email'], self.mailbox_name or ALL_MAILBOXES, self.account['host']))
            
            try:
                self.imap.shutdown()
            except Exception:
                pass # ignore errors shutting down
            
            self.imap = None    
    
    def call(self, cmd, reconnect=True):
        """
        Helper that ensures executes an imaplib command an ensures it's okay.
        Also handles IMAP servers that throttle connections and dropped connections.
        """
        if self.imap is None:
            raise ValueError('Disconnected. Aborting...')
        
        while True:
            try:
                typ, dat = cmd(self.imap)
                if typ != 'OK':
                    raise ValueError('Command failed: %s %s' % (typ, dat))
            except Exception as e:
                msg = unicode(e).lower()
                
                if 'throttle' in msg:
                    logger.warn('Throttle detected. Delay 20s: %s' % e)
                    time.sleep(20)
                    
                elif reconnect and ('broken pipe' in msg or 'connection closed' in msg):
                    logger.warn('Dropped connection detected. Delay 10s and reconnect: %s' % e)
                    time.sleep(10)
                    
                    retries = 0
                    while True:
                        try:
                            self.connect()
                        except Exception:
                            if retries < 10:
                                retries += 1 # try again
                            else:
                                raise # permanent fail
                            time.sleep(10)
                        else:
                            break
                    
                else:
                    raise
            else:
                return typ, dat
    
    def select_mailbox(self, mailbox_name, reconnect=True):
        """
        Selects the mailbox and stores 
        """
        self.mailbox_name = mailbox_name
        
        # select the mailbox if we have been provided one
        try:
            self.call(lambda imap: imap.select(self.mailbox_name), reconnect=reconnect)
        except Exception as e:
            logger.error('%s/%s: Failed to select mailbox: %s' % (
                self.account['email'], self.mailbox_name, e))
            raise
        
    def uid_fetch(self, uids, cmd):
        """
        Performs an IMAP fetch and ensures the result is in the required format.
        We need to do this because sometimes IMAP servers return bad data intermittently.
        """
        if isinstance(uids, (list, set, tuple)):
            uids = b','.join(uids)
        
        typ, dat = self.call(lambda imap: imap.uid(b'FETCH', uids, cmd))
        
        if not dat or not any(dat):
            raise ValueError('Empty response: %s' % repr(dat))
        if not all(len(v) == 2 and len(v[0]) == 2 for v in grouper(2, dat)):
            raise ValueError('Malformed response: %s' % repr(dat))
        
        return typ, dat


#
# Multiprocessing functions
#   
def backup_mailbox(conn, config, account, mailbox_name, mbox_path):
    """
    Backs up a mailbox to an mbox file.
    """
    # load the mbox from disk if it exists and determine the Message-ID's already stored
    parse_message_id_header = lambda message_id: (lambda m: m.group(1) if m else None)(
        MESSAGE_ID_RE.match(SPACE_RE.sub(b' ', message_id.strip())))
    mbox_message_ids = set()
    local_message_ids = set()
    
    if os.path.exists(mbox_path):
        logger.info('%s/%s: Loading existing mbox...' % (
            account['email'], mailbox_name))
        
        with open(mbox_path, 'rb') as f:
            for msg in mailbox.PortableUnixMailbox(f):
                x_mozilla_status = b''.join(msg.getfirstmatchingheader('X-Mozilla-Status'))
                message_id = parse_message_id_header(
                    b''.join(msg.getfirstmatchingheader('Message-ID')))
                
                mbox_message_ids.add(message_id)
                if x_mozilla_status != X_MOZILLA_STATUS_DELETED:
                    local_message_ids.add(message_id)
    
    # select the mailbox
    try:
        conn.select_mailbox(mailbox_name)
    except Exception:
        return
    
    # list the UID's of the mailbox and determine the Message-ID header for each UID
    logger.info('%s/%s: Listing UIDs...' % (
        account['email'], mailbox_name))
    
    try:
        data = conn.call(lambda imap: imap.uid(b'SEARCH', None, b'ALL'))[1]
    except Exception as e:
        logger.error('%s/%s: Failed to list UIDs: %s' % (
            account['email'], mailbox_name, e))
        return
    
    uids = data[0].split()
    
    # fetch the Message-ID's in batches
    header_batch_size = config.get('header_batch_size', 500)
    remote_message_ids = set()
    uids_to_download = []
    uids_without_message_ids = []
    
    for uid_chunk in grouper(header_batch_size, uids):
        logger.info('%s/%s: Fetching %s Message-IDs...' % (
            account['email'], mailbox_name, len(uid_chunk)))
        
        try:
            data = conn.uid_fetch(uid_chunk, 
                b'(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)] UID)')[1]
        except Exception as e:
            logger.error('%s/%s: Failed to retrieve Message-IDs: %s' % (
                account['email'], mailbox_name, e))
            continue
        
        for (unused, message_id), uid in grouper(2, data):
            uid = UID_RE.search(uid).group(1)
            
            message_id = parse_message_id_header(message_id)
            if not message_id:
                uids_without_message_ids.append(uid)
            else:
                remote_message_ids.add(message_id)
                if message_id not in mbox_message_ids:
                    uids_to_download.append(uid)
    
    # handle messages that don't have a Message-ID by generating one from specific headers
    uids_to_download_without_message_ids = []
    
    for uid_chunk in grouper(header_batch_size, uids_without_message_ids):
        logger.info('%s/%s: Fetching %s headers...' % (
            account['email'], mailbox_name, len(uid_chunk)))
        
        try:
            data = conn.uid_fetch(uid_chunk, 
                b'(BODY.PEEK[HEADER.FIELDS (FROM TO CC DATE SUBJECT)] UID)')[1]
        except Exception as e:
            logger.error('%s/%s: Failed to retrieve headers: %s' % (
                account['email'], mailbox_name, e))
            continue
        
        for (unused, headers), uid in grouper(2, data):
            uid = UID_RE.search(uid).group(1)
            message_id = b'<%s@%s>' % (hashlib.sha1(headers.strip()).hexdigest(), 
                IMAPBACKUP_DOMAIN)
            
            remote_message_ids.add(message_id)
            if message_id not in mbox_message_ids:
                uids_to_download_without_message_ids.append((uid, message_id))
    
    # download new messages to the mailbox
    prepare_body_for_mbox = lambda body: \
        body.strip().replace(b'\r', b'').replace(b'\nFrom ', b'\n>From ')
    
    if uids_to_download or uids_to_download_without_message_ids:
        email_batch_size = config.get('email_batch_size', 50)
        
        with open(mbox_path, 'ab') as f:
            # we can download emails with Message-IDs in batch
            for uid_chunk in grouper(email_batch_size, uids_to_download):
                logger.info('%s/%s: Downloading %s emails...' % (
                    account['email'], mailbox_name, len(uid_chunk)))
                
                try:
                    data = conn.uid_fetch(uid_chunk, b'RFC822')[1]
                except Exception as e:
                    logger.error('%s/%s: Failed to retrieve emails: %s' % (
                        account['email'], mailbox_name, e))
                    continue
                
                for (unused, body), unused in grouper(2, data):
                    msg = rfc822.Message(BytesIO(body))
                    message_id = parse_message_id_header(
                        b''.join(msg.getfirstmatchingheader('Message-ID')))
                    
                    if message_id in mbox_message_ids:
                        # avoid writing duplicates to mbox, can happen when moved between folders
                        logger.warn('%s/%s: Attempted to write email with duplicate '
                            'Message-ID %s to mbox. Skipping...' % (
                                account['email'], mailbox_name, message_id))
                        continue
                    local_message_ids.add(message_id)
                    mbox_message_ids.add(message_id)
                    
                    f.write(b''.join([
                        b'From nobody %s\n' % time.ctime(),
                        X_MOZILLA_STATUS_READ,
                        prepare_body_for_mbox(body),
                        b'\n\n',
                        ]))
            
            # we must download emails without Message-IDs individually 
            # so we can assign them their new Message-ID
            for uid, message_id in uids_to_download_without_message_ids:
                logger.info('%s/%s: Downloading email UID (%s)...' % (
                    account['email'], mailbox_name, uid))
                
                try:
                    body = conn.uid_fetch(uid, b'RFC822')[1][0][1]
                except Exception as e:
                    logger.error('%s/%s: Failed to retrieve email: %s' % (
                        account['email'], mailbox_name, e))
                    continue
                
                local_message_ids.add(message_id)
                mbox_message_ids.add(message_id)
                
                f.write(b''.join([
                    b'From nobody %s\n' % time.ctime(),
                    X_MOZILLA_STATUS_READ,
                    b'Message-ID: %s\n' % message_id,
                    prepare_body_for_mbox(body),
                    b'\n\n',
                    ]))
    
    # set deleted messages to X-Mozilla-Status: 0009 by overwriting the header in-place
    # set restored messages to X-Mozilla-Status: 0001 by overwriting the header in-place
    deleted_message_ids = local_message_ids - remote_message_ids
    restored_message_ids = (mbox_message_ids - local_message_ids) & remote_message_ids
    
    if deleted_message_ids or restored_message_ids:
        logger.info('%s/%s: Deleting %s emails and restoring %s emails...' % (
            account['email'], mailbox_name, len(deleted_message_ids), len(restored_message_ids)))
        
        with open(mbox_path, 'r+b') as f:
            for msg in mailbox.PortableUnixMailbox(f):
                message_id = parse_message_id_header(
                    b''.join(msg.getfirstmatchingheader('Message-ID')))
                
                is_deleted = message_id in deleted_message_ids
                is_restored = message_id in restored_message_ids
                
                if is_deleted or is_restored:
                    msg.fp.seek(len(msg.unixfrom))
                    offset = f.tell()
                    x_mozilla_status = f.read(len(X_MOZILLA_STATUS_READ))
                    
                    if is_deleted:
                        assert x_mozilla_status == X_MOZILLA_STATUS_READ, \
                            '%s[%s]: expected %s at offset %s, found %s' % (mbox_path, message_id, 
                                repr(X_MOZILLA_STATUS_READ), offset, repr(x_mozilla_status))
                    else:
                        assert x_mozilla_status == X_MOZILLA_STATUS_DELETED, \
                            '%s[%s]: expected %s at offset %s, found %s' % (mbox_path, message_id, 
                                repr(X_MOZILLA_STATUS_DELETED), offset, repr(x_mozilla_status))
                    
                    msg.fp.seek(len(msg.unixfrom))
                    
                    if is_deleted:
                        f.write(X_MOZILLA_STATUS_DELETED)
                    else:
                        f.write(X_MOZILLA_STATUS_READ)


def backup_mailbox_worker(config, oauth_tokens, account, mailbox_queue):
    """
    Worker process for backing up the mailboxes in the mailbox queue for the given account.
    """
    try:
        with IMAPConnection(config, oauth_tokens, account) as conn:
            try:
                conn.connect()
            except Exception:
                return
            
            while True:
                try:
                    m = mailbox_queue.get(block=True, timeout=1)
                except Queue.Empty:
                    return # exit when queue consumed
                
                mailbox_name, mbox_path = m
                backup_mailbox(conn, config, account, mailbox_name, mbox_path)
      
    except Exception:
        traceback.print_exc()


#
# Main functions
#
def get_account_mailboxes(config, oauth_tokens, account):
    """
    Returns the mailboxes and their mbox paths to backup for a given account.
    """    
    # connect to the IMAP server for this account
    with IMAPConnection(config, oauth_tokens, account) as conn:
        try:
            conn.connect()
        except Exception:
            return
        
        # list all mailboxes of the account
        logger.info('%s/%s: Listing mailboxes...' % (
            account['email'], ALL_MAILBOXES))
        
        try:
            data = conn.call(lambda imap: imap.list())[1]
        except Exception as e:
            logger.error('%s/%s: Failed to list mailboxes: %s' % (
                account['email'], ALL_MAILBOXES, e))
            return
    
    # prepare the folder where the mbox files will be stored for this account
    account_path = os.path.join(config['destination'], account['email'])
    
    if not os.path.exists(account_path):
        os.makedirs(account_path)    
    
    # return the list of mailboxes, ignoring specified mailboxes
    ignore_mailboxes = (set(config.get('ignore_mailboxes', [])) | 
        set(account.get('ignore_mailboxes', [])))
    mailboxes = []
    
    for list_result in data:
        m = LIST_RE.match(list_result.strip())
        delimiter = m.group(1)
        mailbox_name = m.group(2)
        mailbox_parts = mailbox_name.strip('"').split(delimiter)
        
        if any(m in ignore_mailboxes for m in mailbox_parts):
            continue
        
        mbox_filename = '%s.mbox' % FILENAME_RE.sub('', '.'.join(mailbox_parts))
        mbox_path = os.path.join(account_path, mbox_filename)
        mailboxes.append((mailbox_name, mbox_path))
    
    return mailboxes


def authenticate_oauth2_tokens(config):
    """
    Authenticates with various OAuth2 providers and return their access tokens by connection name.
    """
    tokens = {}
    cache_path = config.get('oauth2_cache', SCRIPT_DIR)
    
    for name, conn in config.get('oauth2', {}).items():
        if conn['type'] == 'o365':
            try:
                import msal
            except ImportError:
                logger.error('Failed to import msal library required to connect to Office 365. '
                    'Install via "pip install msal" before trying again.')
                return None
            
            authority = "https://login.microsoftonline.com/" + conn['tenant_id']
            scopes = ["https://outlook.office.com/IMAP.AccessAsUser.All"]
            cache = msal.SerializableTokenCache()
            
            cache_file = os.path.join(cache_path, 'oauth2_o365_' + name + '.json')
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    cache.deserialize(f.read())
            
            app = msal.PublicClientApplication(conn['client_id'], 
                authority=authority, 
                token_cache=cache)
            
            accounts = app.get_accounts()
            result = app.acquire_token_silent(scopes, account=accounts[0]) if accounts else None
            
            if result is None:
                logger.info('%s: Connecting to Office 365 Oauth (%s)...' % (
                    conn['email'], conn['tenant_id']))
                
                state = str(uuid.uuid4())
                redirect_uri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
                auth_url = app.get_authorization_request_url(scopes, state=state, 
                    redirect_uri=redirect_uri, login_hint=conn.get('email'))
                
                print('1. Open the following URL in your browser:')
                print(auth_url)
                print('2. Sign in to Office 365.')
                result_url = raw_input('3. You will be redirected to an empty page. '
                    'Paste the page URL here: ')
                
                auth_code = parse_qs(urlparse(result_url).query)['code'][0]
                result = app.acquire_token_by_authorization_code(auth_code, scopes=scopes, 
                    redirect_uri=redirect_uri)
            
            tokens[name] = result['access_token']
            
            with open(cache_file, 'wb') as f:
                f.write(cache.serialize())
                        
        else:
            logger.error('Unknown oauth2 type of: %s. Specify one of: o365' % 
                conn['type'])
            return None
    
    return tokens


def main():
    """
    Runs the backup.
    """
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print('Usage: python imap_backup.py [path/to/config.json]')
        return
    
    # load the config file
    config_path = 'config.json'
    if len(sys.argv) > 1: 
        config_path = sys.argv[1]
    
    with open(config_path, 'rb') as f: 
        config = json.load(f)
    
    # authenticate any oauth tokens first
    oauth_tokens = authenticate_oauth2_tokens(config)
    if oauth_tokens is None:
        return 1
    
    # find all mailboxes for all mail accounts and create a N number of processes per account
    processes_per_account = config.get('processes_per_account', 2)
    pending_processes = []
    
    for account in config['accounts']:
        mailbox_queue = multiprocessing.Queue()
        for m in get_account_mailboxes(config, oauth_tokens, account):
            mailbox_queue.put(m)
        for _ in range(account.get('processes_per_account', processes_per_account)):
            pending_processes.append(multiprocessing.Process(target=backup_mailbox_worker, 
                args=(config, oauth_tokens, account, mailbox_queue)))
    
    pending_processes.reverse()
    
    # start the processes ensuring that only the number of running processes is always 
    # less than total_processes
    total_processes = config.get('total_processes', 4)
    active_processes = []
    
    while active_processes or pending_processes:
        while len(active_processes) < total_processes and pending_processes:
            p = pending_processes.pop()
            p.start()
            active_processes.append(p)
        
        time.sleep(1)
        active_processes = [p for p in active_processes if p.is_alive()]
    
    # call a success url if defined
    if config.get('success_url'):
        try:
            urllib2.urlopen(config['success_url']).read()
        except Exception as e:
            logger.error('Failed to check-in at the success URL: %s %s' % (
                type(e), e))


if __name__ == '__main__':
    sys.exit(main())
