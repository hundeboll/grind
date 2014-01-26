`grind` - A Client for Google Drive
=========================================

`grind` is yet another client for Google Drive. It is written in python as a reaction to missing features and bugs of the currently existing alternatives. It is primarily meant to satisfy the needs of the author, but ideas, suggestions, bug reports, and patches are always welcome.

Features
--------

A few features that distinguishes `grind` from other Google Drive clients:

* Multi-threaded uploads - exploits fast upload connections better by issuing multiple http-requests concurrently.
* Proper error handling - retry uploads when an error is reported by the server.
* Full unicode support - correctly handles file and folder names with unicode characters, instead of uploading duplicate files.

It would of course had been better to add the missing features to the existing clients, but they were either too complex or written in other unmastered programming languages.

Files are compared on modification date and file size. If the date has changed locally, the file is compared with a md5sum hash to avoid unneeded uploads. If only the date is changed, but the contents stay the same, `grind` will update the date in Drive.

Roadmap
-------

So far it is only possible to push a folder and its contents to drive. It is planned to add the following features in a non-prioritized order:

* Pull synchronization
* Deletion of removed local/remote files
* Resume interrupted syncs without resolving again
* Syncing only specified folders/files in Drive
* ...

Dependencies
------------

`grind`is written in python, and since the Google API Client only supports python2, so does `grive`. It uses the following non-standard python modules:

* google-api-python-client - for handling all the nasty http stuff
* oauth2client - for signing in on Google Drive
* httplib2 - for doing http requests/responses with Google API Client
* pytz - for timezone support
* magic - for better mime type detection

Usage
-----

To simply synchronize the current folder, start `grind` with no arguments. You can specify the folder to synchronize as the last argument:

```
$ python grind.py ~/Drive

[#         ] 17.08% 476/1308 files 4.52/26.49 GB
```

At first `grind` will ask you to open a URL and allow `grive` to access your Drive account. It will then download a list of files and compare this to your local folder and then start uploading any files that are missing in Drive. The first steps might take a while depending on the number of files in Drive.

### Verbose

To follow the process, start `grind` with the verbose flag:

```
$ python grind.py --verbose ~/Drive

2014-01-19 10:05:33,283 ./grind.py INFO: resolving drive files (0 files received)
2014-01-19 10:05:43,914 ./grind.py INFO: resolving drive files (1000 files received)
2014-01-19 10:07:44,055 ./grind.py INFO: resolved 1308 files/folders
2014-01-19 10:07:44,056 ./grind.py INFO: building drive tree
2014-01-19 10:07:44,221 ./grind.py WARNING: duplicate file path: photos/20130730_abb_lysefjord/IMG_0054.JPG
2014-01-19 10:07:44,254 ./grind.py INFO: resolving local files
2014-01-19 10:07:48,157 ./grind.py INFO: files new: 1062 (26.49 GB)
2014-01-19 10:07:48,157 ./grind.py INFO: files changed: 0 (0 B)
2014-01-19 10:07:48,157 ./grind.py INFO: files meta changed: 0
2014-01-19 10:07:48,157 ./grind.py INFO: files unchanged: 1308 (3.86 GB)
2014-01-19 10:07:48,410 ./grind.py INFO: updating meta changed files
2014-01-19 10:07:48,665 ./grind.py INFO: updating changed files
2014-01-19 10:07:48,665 ./grind.py INFO: creating directories
2014-01-19 10:07:48,985 ./grind.py INFO: uploading new files

[#         ] 17.08% 476/1308 files 4.52/26.49 GB
```

This prints out the process of downloading the file list from Drive, and gives you a report on the work needed to be done. There is also a debug flag available, which will spam you with files and folders :)

### Resolve Only

If you only want to know what `grind` intends to do, run it with the resolve-only flag:

```
$ python grind.py --verbose --resolve-only ~/Drive

2014-01-19 10:05:33,283 ./grind.py INFO: resolving drive files (0 files received)
2014-01-19 10:05:43,914 ./grind.py INFO: resolving drive files (1000 files received)
2014-01-19 10:07:44,055 ./grind.py INFO: resolved 1308 files/folders
2014-01-19 10:07:44,056 ./grind.py INFO: building drive tree
2014-01-19 10:07:44,221 ./grind.py WARNING: duplicate file path: photos/20130730_abb_lysefjord/IMG_0054.JPG
2014-01-19 10:07:44,254 ./grind.py INFO: resolving local files
2014-01-19 10:07:48,157 ./grind.py INFO: files new: 1062 (26.49 GB)
2014-01-19 10:07:48,157 ./grind.py INFO: files changed: 0 (0 B)
2014-01-19 10:07:48,157 ./grind.py INFO: files meta changed: 0
2014-01-19 10:07:48,157 ./grind.py INFO: files unchanged: 1308 (3.86 GB)

$
```

### Threads

One of the main features of `grind` is the ability to do simultaneous uploads. To enable this, use the threads flag:

```
$ python grind.py --verbose --threads 5 ~/Drive

2014-01-19 10:05:33,283 ./grind.py INFO: resolving drive files (0 files received)
2014-01-19 10:05:43,914 ./grind.py INFO: resolving drive files (1000 files received)
2014-01-19 10:07:44,055 ./grind.py INFO: resolved 1308 files/folders
2014-01-19 10:07:44,056 ./grind.py INFO: building drive tree
2014-01-19 10:07:44,221 ./grind.py WARNING: duplicate file path: photos/20130730_abb_lysefjord/IMG_0054.JPG
2014-01-19 10:07:44,254 ./grind.py INFO: resolving local files
2014-01-19 10:07:48,157 ./grind.py INFO: files new: 1062 (26.49 GB)
2014-01-19 10:07:48,157 ./grind.py INFO: files changed: 0 (0 B)
2014-01-19 10:07:48,157 ./grind.py INFO: files meta changed: 0
2014-01-19 10:07:48,157 ./grind.py INFO: files unchanged: 1308 (3.86 GB)
2014-01-19 10:07:48,410 ./grind.py INFO: updating meta changed files
2014-01-19 10:07:48,665 ./grind.py INFO: updating changed files
2014-01-19 10:07:48,665 ./grind.py INFO: creating directories
2014-01-19 10:07:48,985 ./grind.py INFO: uploading new files
2014-01-19 10:07:49,230 ./grind.py INFO: uploading new files
2014-01-19 10:07:49,487 ./grind.py INFO: uploading new files
2014-01-19 10:07:49,806 ./grind.py INFO: uploading new files
2014-01-19 10:07:50,398 ./grind.py INFO: uploading new files

[#         ] 17.08% 476/1308 files 4.52/26.49 GB
```

Notice the repeated number of uploading-messages in the end - one for each thread.

### Help

To see more options, run `grind` with the help flag:

```
$ python grind.py --help
usage: grind.py [-h] [-v] [-d] [-c CREDENTIALS] [-r] [-u] [-p] [-m]
                [-t THREADS]
                [path]

Upload new files to Google Drive

positional arguments:
  path                  path to push

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         enable verbose logging
  -d, --debug           enable debug logging
  -c CREDENTIALS, --credentials CREDENTIALS
                        path to credentials file
  -r, --resolve-only    do not upload/update anything
  -u, --disable-upload  do not upload new files
  -p, --disable-update  do not update changed files
  -m, --disable-meta    do not update changed meta data
  -t THREADS, --threads THREADS
                        number of simultanious transmissions
```
