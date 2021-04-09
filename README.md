# imap_backup

imap_backup is a multi-threaded multi-account IMAP backup script that stores emails in mbox files. It
requires Python 2.7.

It has the following features:

- Mailboxes across accounts, or the same account, are downloaded in parallel via multiprocessing.

- Emails are uniquely identified by their Message-ID, with a Message-ID generated if they don't 
  have one. Already downloaded emails are skipped.
  
- Retrieval of Message-ID's and emails are in done batches of 500 and 50 respectively (configurable). 
  This avoids thousands of calls to the IMAP server and greatly speeds up backups.

- Deleted emails are marked as deleted using X-Mozilla-Status, but the email is not removed
  from the mbox. This allows recovery of deleted emails.
  
- Connection errors are retried, and output to the console but processing is not aborted. 
  This is to ensure the failure of one mailbox, or temporary service issues, don't affect the backup 
  of other mailboxes. It is presumed that errors will have been resolved by the next backup run 
  where it can try again.
  

## How to run

1. Copy config.json.example to config.json.

```
{
    "destination": "/path/to/email_backup",
    "total_processes": 3,
    "processes_per_account": 2,
    "ignore_mailboxes": [
        "Calendar",
        "Contacts",
        "Conversation History",
        "Journal",
        "Quick Step Settings",
        "RSS Feeds",
        "Suggested Contacts",
        "Sync Issues",
        "Tasks",
        "Working Set"
        ],
    "accounts": [
        {
            "email": "john@microsoft.com",
            "password": "password1", 
            "host": "outlook.office365.com",
            "processes_per_account": 1
        },
        { 
            "email": "jill@microsoft.com",
            "password": "password2", 
            "host": "outlook.office365.com"
        }
    ]
}
```

2. Add your accounts and adjust the settings as required. Descriptions of each setting are as follows:

`destination` - The path where you want to store your email backups.

`total_processes` - The total number of processes to be backing up at any time. Default 4.

`processes_per_account` - The maximum processes allowed to backup a single account at any time. 
Ensure this doesn't exceed the maximum number of connections allowed by your IMAP server per 
email address. Default 2.

`success_url` - A URL to GET upon successful completion. Allows checking-in to ensure backups are 
run successfully.

`ignore_mailboxes` - A list of mailbox names to ignore. A good set of defaults is included in the 
.example.

`timeout` - Socket timeout in seconds. Default 120.

`header_batch_size` - The number of Message-ID headers to retrieve in each batch. Default 500.

`email_batch_size` - The number of emails to download in each batch. Default 50.

`accounts` - A list of dictionaries with the following settings:

`accounts.username` - The login username (generally the email address) of the IMAP account.

`accounts.password` - The login password of the IMAP account.

`accounts.email` - The email address of the IMAP account.

`accounts.host` - The IMAP host.

`accounts.ssl` - Whether to connect to the host over SSL. Default true.

`accounts.processes_per_account` - An override that reduces the maximum number of connections that 
are allowed to this IMAP host. Default `processes_per_account`.

3. Then simply run:

`python imap_backup.py`

Or add it to your cron and enjoy daily/weekly/monthly IMAP backups.


## Connecting via OAuth2

If your provider only supports OAuth authentication, then you can specify connection details in
the `oauth2` section of config.json. Currently only Office 365 is supported.

### Office 365

Ask your Office 365 administrator to add a new App Registration with the following settings, and to
provide you with the corresponding Client ID and Tenant ID of the application.

API Permissions (With admin consent granted):
- IMAP.AccessAsUser.All
- offline_access

Redirect URI:
- https://login.microsoftonline.com/common/oauth2/nativeclient

Then update config.json similar to below:

```
{
    "oauth2": {
       "john": {
          "type": "o365",
          "client_id": "YOUR-CLIENT-ID-HERE",
          "tenant_id": "YOUR-TENANT-ID-HERE",
          "email": "john@microsoft.com"
        },
        "jill": {
          "type": "o365",
          "client_id": "YOUR-CLIENT-ID-HERE",
          "tenant_id": "YOUR-TENANT-ID-HERE",
          "email": "jill@microsoft.com"
        }
    },
    "accounts": [
        {
            "email": "john@microsoft.com",
            "oauth2": "john", 
            "host": "outlook.office365.com",
            "processes_per_account": 1
        },
        { 
            "email": "jill@microsoft.com",
            "oauth2": "jill", 
            "host": "outlook.office365.com"
        }
    ]  
}
```


## License

Copyright &copy; 2021 Ryan Butterfield of Master Apps (https://github.com/masterapps-au)

Freely distributable under the terms of the MIT license.
