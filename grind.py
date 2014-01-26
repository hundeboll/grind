#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
Copyright (c) 2014 Martin Hundebøll
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from oauth2client.client import OAuth2WebServerFlow, FlowExchangeError, OAuth2Credentials
from apiclient.discovery import build
from apiclient.http import MediaFileUpload
from apiclient import errors
from httplib import BadStatusLine
from os.path import expanduser
import dateutil.parser
import threading
import datetime
import argparse
import httplib2
import hashlib
import logging
import socket
import magic
import time
import pytz
import sys
import os

p = argparse.ArgumentParser(description='Upload new and changed files to Google Drive')

p.add_argument('path',
        type=unicode,
        default='.',
        nargs='?',
        help='path to push')

p.add_argument('-v', '--verbose',
        action='store_true',
        help='enable verbose logging')

p.add_argument('-d', '--debug',
        action='store_true',
        help='enable debug logging')

p.add_argument('-c', '--credentials',
        type=str,
        default=expanduser('~') + '/.grind/creds.json',
        help='path to credentials file')

p.add_argument('-r', '--resolve-only',
        action='store_true',
        dest='resolve',
        help='do not upload/update anything')

p.add_argument('-u', '--disable-upload',
        action='store_true',
        dest='disable_upload',
        help='do not upload new files')

p.add_argument('-p', '--disable-update',
        action='store_true',
        dest='disable_update',
        help='do not update changed files')

p.add_argument('-m', '--disable-meta',
        action='store_true',
        dest='disable_meta',
        help='do not update changed meta data')

p.add_argument('-t', '--threads',
        type=int,
        default=1,
        help='number of simultanious transmissions')

logger = logging.getLogger(__file__)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class remote_file(object):
    def __init__(self, info):
        self.info = info
        self.path = None

    @property
    def id(self):
        return self.info['id']

    @property
    def title(self):
        return self.info['title']

    @property
    def size(self):
        return int(self.info.get('fileSize', 0))

    @property
    def md5sum(self):
        return self.info['md5Checksum']

    @property
    def parent_id(self):
        return self.info['parents'][0]['id']

    @property
    def is_folder(self):
        return self.info['mimeType'] == 'application/vnd.google-apps.folder'

    @property
    def has_parents(self):
        return len(self.info['parents']) > 0

    @property
    def is_root(self):
        return self.info['parents'][0]['isRoot']

    @property
    def modified_date(self):
        return dateutil.parser.parse(self.info['modifiedDate'])

class remote(object):
    backoff_time = 1
    file_index = {}
    file_paths = {}
    file_items = []
    folder_index = {}
    total_size = 0
    upload_size = 0
    upload_count = 0
    update_size = 0
    update_count = 0

    def __init__(self, args):
        self.cred_path = args.credentials
        self.path = args.path + '/'

        if os.path.isfile(self.cred_path):
            self.authenticate_saved()
        else:
            self.authenticate_new()

        self.http = self.authorize()
        self.drive = self.create_drive()

    def authenticate_new(self):
        CLIENT_ID = '472054675343-83t5nuooa4u0180tf3o80j74hd0sh3pp.apps.googleusercontent.com'
        CLIENT_SECRET = 'A_Jqz_0bh9nlZW_F9M7ItYOw'
        SCOPE = 'https://www.googleapis.com/auth/drive'
        REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'

        self.flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, SCOPE, REDIRECT_URI)

        auth_uri = self.flow.step1_get_authorize_url()
        print('Go to the following link in your browser: ' + auth_uri)
        code = raw_input('Enter verification code: ').strip()

        try:
            self.credentials = self.flow.step2_exchange(code)
        except FlowExchangeError as e:
            logger.error("unable to authenticate: " + e.message)
            sys.exit(1)

        cred_folder = os.path.dirname(self.cred_path)
        if not os.path.exists(cred_folder):
            os.makedirs(cred_folder)

        json = self.credentials.to_json()
        f = open(self.cred_path, 'wb')
        f.write(json)
        f.close()

    def authenticate_saved(self):
        try:
            f = open(self.cred_path, 'rb')
            json = f.read()
            self.credentials = OAuth2Credentials.from_json(json)
        except ValueError as e:
            logger.error('unable to load credentials: {}'.format(e))
            self.authenticate_new()

    def authorize(self):
        http = httplib2.Http()
        return self.credentials.authorize(http)

    def create_drive(self, http=None):
        if not http:
            http=self.http

        drive = build('drive', 'v2', http=http)

        if drive is None:
            logger.error("Failed to create drive object")
            sys.exit(1)

        return drive

    def get_file_list(self):
        fields = ['createdDate',
                  'downloadUrl',
                  'fileExtension',
                  'fileSize',
                  'id',
                  'kind',
                  'md5Checksum',
                  'mimeType',
                  'modifiedByMeDate',
                  'modifiedDate',
                  'originalFilename',
                  'title',
                  'parents(id,isRoot)']

        page_token = None

        while True:
            try:
                param = {'q': 'trashed=false',
                         'maxResults': 1000,
                         'fields': 'items(' + ','.join(fields) + '),nextPageToken'}
                logger.info("resolving drive files ({} files received)".format(len(self.file_items)))

                if page_token:
                    param['pageToken'] = page_token

                files = self.drive.files().list(**param).execute()
                file_list = [remote_file(item) for item in files['items']]

                self.file_items.extend(file_list)
                page_token = files.get('nextPageToken')
                self.backoff_time = 1

                if not page_token:
                    break
            except errors.HttpError as e:
                logger.error("Failed to receive file list from drive: {}".format(e))
                time.sleep(self.backoff_time)
                self.backoff_time *= 2

        logger.info('resolved {} files/folders'.format(len(self.file_items)))

    def build_tree(self):
        logger.info('building drive tree')

        for info in self.file_items:
            self.file_index[info.id] = info

        for info in self.file_items:
            if info.is_folder:
                if info.title in self.folder_index:
                    logger.warning('duplicate folder name: ' + title)

                self.folder_index[info.title] = info
                continue

            path = self.recurse_tree(info)

            if path in self.file_paths:
                logger.warning('duplicate file path: ' + path)

            info.path = path
            self.file_paths[path] = info
            self.total_size += info.size
            logger.debug("drive file: " + path)

    def recurse_tree(self, info, path = None):
        if path:
            path = os.path.join(info.title, path)
        else:
            path = info.title

        if not info.has_parents:
            return path

        if info.is_root:
            return path

        parent_id = info.parent_id
        parent = self.file_index[parent_id]

        return self.recurse_tree(parent, path)

    def create_folder(self, folder_name, parent_id = None):
        logger.debug('creating folder: ' + folder_name)
        body = {
                'title': folder_name,
                'mimeType': "application/vnd.google-apps.folder"
        }

        if parent_id:
            body['parents'] = [{'id': parent_id}]

        new_folder = self.drive.files().insert(body = body).execute()
        self.folder_index[folder_name] = new_folder

        return new_folder['id']

    def create_file(self, path, parent_id, date, mime, drive=None):
        if not drive:
            drive = self.drive

        logger.debug('creating file: ' + path)
        date = date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        path = os.path.join(self.path, path)
        media_body = MediaFileUpload(path, mimetype=mime, resumable=True)

        body = {
                'title': os.path.basename(path),
                'modifiedDate': date,
                'mimeType': mime,
        }

        if parent_id:
            body['parents'] = [{'id': parent_id}]

        while True:
            try:
                file_info = drive.files().insert(
                    body=body,
                    media_body=media_body).execute()
                break
            except errors.HttpError as e:
                logger.error('upload failed: {}'.format(e))
                time.sleep(self.backoff_time)
                self.backoff_time *= 2
            except (socket.error, BadStatusLine) as e:
                logger.debug("upload interrupted {}".format(e))
                return

        self.backoff_time = 1
        self.upload_size += int(file_info['fileSize'])
        self.upload_count += 1

    def update_file(self, path, date, drive=None):
        logger.debug("updating file: " + path)
        if not drive:
            drive = self.drive

        file_id = self.file_paths[path].id
        date = date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        path = os.path.join(self.path, path)
        media_body = MediaFileUpload(path, resumable=True)

        body = {
                'modifiedDate': date,
        }

        while True:
            try:
                file_info = drive.files().update(
                    fileId=file_id,
                    body=body,
                    media_body=media_body).execute()
                break
            except errors.HttpError as e:
                logger.error('upload failed: {}'.format(e))
                time.sleep(self.backoff_time)
                self.backoff_time *= 2
            except (socket.error, BadStatusLine) as e:
                logger.debug("upload interrupted {}".format(e))
                return

        self.backoff_time = 1
        self.update_size += int(file_info['fileSize'])
        self.update_count += 1

    def meta_update_file(self, path, date, drive=None):
        logger.debug("updating file meta: " + path)
        if not drive:
            drive = self.drive

        file_id = self.file_paths[path].id
        date = date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        info = {'modifiedDate': date}

        while True:
            try:
                # Rename the file.
                updated_file = drive.files().patch(
                    fileId=file_id,
                    body=info,
                    setModifiedDate=True,
                    fields='modifiedDate').execute()
                break
            except errors.HttpError as e:
                logger.error('update failed: {}'.format(e))
                time.sleep(self.backoff_time)
                self.backoff_time *= 2
            except (socket.error, BadStatusLine) as e:
                logger.debug("update interrupted {}".format(e))
                return

        self.backoff_time = 1

class local(object):
    file_paths = []
    changed_files = {}
    new_files = {}
    meta_files = {}
    total_size = 0
    changed_size = 0
    new_size = 0
    unchanged_files = {}
    unchanged_size = 0

    def __init__(self, args):
        self.args = args
        self.path = args.path + '/'

    def read_file_list(self):
        logger.info("resolving local files")

        for root, dirs, files in os.walk(self.path):
            files = [f for f in files if not f[0] == '.']
            dirs[:] = [d for d in dirs if not d[0] == '.']

            for f in files:
                path = os.path.join(root, f)
                path = path[len(self.path):]
                info = self.read_file_info(path)
                self.total_size += info['fileSize']
                self.file_paths.append(path)

    def read_file_info(self, path):
        path = os.path.join(self.path, path)
        stats = os.stat(path)
        date = datetime.datetime.fromtimestamp(stats.st_ctime)
        date = date.replace(tzinfo=pytz.UTC)
        us = date.microsecond
        date = date.replace(microsecond=(us - (us % 1000)))
        mime = magic.from_file(path, mime=True)

        return {'fileSize': stats.st_size,
                'modifiedDate': date,
                'mimeType': mime}

    def md5sum(self, path, block_size=2**20):
        md5 = hashlib.md5()
        path = os.path.join(self.path, path)
        f = open(path, 'rb')

        while True:
            data = f.read(block_size)

            if not data:
                break

            md5.update(data)

        return md5.hexdigest()

class grind(object):
    stop = False
    https = []
    threads_running = 0
    threads_done = 0

    def __init__(self, args):
        self.threads = args.threads
        self.remote = remote(args)
        self.local = local(args)

        self.remote.get_file_list()
        self.remote.build_tree()

        self.local.read_file_list()

        self.compare_files()
        self.print_summary()

    def update_progress(self):
        total_bytes = self.local.new_size + self.local.changed_size
        status_bytes = self.remote.upload_size
        total_count = len(self.local.new_files) + len(self.local.changed_files)
        status_count = self.remote.upload_count + self.remote.update_count
        total_size,unit = self.scale_bytes(total_bytes)
        status_size,unit = self.scale_bytes(status_bytes, unit)
        progress_count = float(status_bytes) / float(total_bytes)
        progress_str = '#' * int(progress_count*10)

        progress_string = ' [{0:10}] {1:>2}%'
        string = progress_string.format(progress_str, round(progress_count*100, 2))
        string += " {}/{} files".format(status_count, total_count)
        string += " {}/{} {}".format(status_size, total_size, unit)
        string += "\r"

        sys.stdout.write(string)
        sys.stdout.flush()

    def print_summary(self):
        count = len(self.local.new_files)
        size,unit = self.scale_bytes(self.local.new_size)
        logger.info('files new: {} ({} {})'.format(count, size, unit))

        count = len(self.local.changed_files)
        size,unit = self.scale_bytes(self.local.changed_size)
        logger.info('files changed: {} ({} {})'.format(count, size, unit))

        count = len(self.local.meta_files)
        logger.info('files meta changed: {}'.format(count))

        count = len(self.local.unchanged_files)
        size,unit = self.scale_bytes(self.local.unchanged_size)
        logger.info('files unchanged: {} ({} {})'.format(count, size, unit))

    def scale_bytes(self, bytes_, fixed=None):
        for s,u in ((30,'GB'), (20,'MB'), (10,'kB'), (0,'B')):
            r = bytes_ >> s
            if not r and fixed != u:
                continue

            if s:
                r += (bytes_ - (r << s) >> (s - 10))/1024.0

            return round(r, 2),u

        return 0,'B'

    def compare_files(self):
        for path in self.local.file_paths:
            info = self.local.read_file_info(path)

            if path not in self.remote.file_paths:
                logger.debug("local new: " + path)
                self.local.new_files[path] = info
                self.local.new_size += info['fileSize']
            elif self.file_is_changed(path, info, checksum=True):
                logger.debug("local changed: " + path)
                self.local.changed_files[path] = info
                self.local.changed_size += info['fileSize']
            elif self.file_is_changed(path, info, checksum=False):
                logger.debug("local meta changed: " + path)
                self.local.meta_files[path] = info
            else:
                logger.debug("local unchanged: " + path)
                self.local.unchanged_files[path] = info
                self.local.unchanged_size += info['fileSize']

        self.local.new_files = sorted(self.local.new_files)
        self.local.changed_files = sorted(self.local.changed_files)

    def file_is_changed(self, path, local_info, checksum=False):
        if path not in self.remote.file_paths:
            return True

        remote_info = self.remote.file_paths[path]

        local_date = local_info['modifiedDate']
        local_size = local_info['fileSize']

        if (local_date != remote_info.modified_date or local_size != remote_info.size) and checksum:
            return remote_info.md5sum != self.local.md5sum(path)

        if (local_date != remote_info.modified_date or local_size != remote_info.size) and not checksum:
            return True

        return False

    def drive_create_path(self, path):
        folders,filename = os.path.split(path)
        parent_id = None

        if not folders:
            return

        for folder in folders.split(os.sep):
            if folder not in self.remote.folder_index:
                parent_id = self.remote.create_folder(folder, parent_id)
            else:
                parent_id = self.remote.folder_index[folder].id

    def drive_create_paths(self):
        logger.info("creating directories")
        for path in self.local.new_files:
            self.drive_create_path(path)

    def drive_upload_file(self, path, drive=None):
        if not drive:
            drive = self.drive
        folder_path,file_name = os.path.split(path)

        if folder_path:
            folder_parent = os.path.basename(folder_path)
            folder_info = self.remote.folder_index[folder_parent]
            folder_id = folder_info['id']
        else:
            folder_id = None

        date = self.local.read_file_info(path)['modifiedDate']
        mime = self.local.read_file_info(path)['mimeType']
        self.remote.create_file(path, folder_id, date, mime, drive)

    def drive_upload_files(self, file_list=None, drive=None):
        logger.info("uploading new files")
        if not file_list:
            file_list = self.local.new_files

        if not drive:
            drive = self.drive

        for path in file_list:
            self.drive_upload_file(path, drive)
            if self.stop:
                break

        self.threads_done += 1
        logger.debug("upload thread done")

    def drive_meta_update_files(self, file_list=None, drive=None):
        logger.info("updating meta changed files")
        if not file_list:
            file_list = self.local.meta_files

        if not drive:
            drive = self.drive

        for path in file_list:
            date = self.local.read_file_info(path)['modifiedDate']
            self.remote.meta_update_file(path, date, drive)

        self.threads_done += 1
        logger.debug("meta update thread done")

    def drive_update_files(self, file_list=None, drive=None):
        logger.info("updating changed files")
        if not file_list:
            file_list = self.local.changed_files

        if not drive:
            drive = self.drive

        for path in file_list:
            date = self.local.read_file_info(path)['modifiedDate']
            self.remote.update_file(path, date, drive)

        self.threads_done += 1
        logger.debug("update thread done")

    def kill_threads(self):
        self.stop = True
        logger.info('closing sockets')
        for http in self.https:
            for conn in http.connections.values():
                if hasattr(conn, 'sock') and conn.sock:
                    conn.sock.shutdown(socket.SHUT_WR)
                    conn.sock.close()

    def start_meta_update_thread(self):
        http = self.remote.authorize()
        self.https.append(http)
        drive = self.remote.create_drive(http)
        l = self.local.meta_files
        t = threading.Thread(target=self.drive_meta_update_files, args=[l, drive])
        t.start()
        self.threads_running += 1

    def start_update_thread(self):
        http = self.remote.authorize()
        self.https.append(http)
        drive = self.remote.create_drive(http)
        l = self.local.changed_files
        t = threading.Thread(target=self.drive_update_files, args=[l, drive])
        t.start()
        self.threads_running += 1

    def start_upload_threads(self):
        n = self.threads
        self.https = []

        for i in range(n):
            http = self.remote.authorize()
            self.https.append(http)
            drive = self.remote.create_drive(http)

            l = self.local.new_files[i::n]
            t = threading.Thread(target=self.drive_upload_files, args=[l, drive])
            t.start()
            self.threads_running += 1

        while self.threads_done < self.threads_running:
            time.sleep(1)
            self.update_progress()
        logger.debug("main done")

if __name__ == "__main__":
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        g = grind(args)

        if args.resolve:
            sys.exit(0)

        if not args.disable_meta:
            g.start_meta_update_thread()

        if not args.disable_update:
            g.start_update_thread()

        if not args.disable_upload:
            g.drive_create_paths()
            g.start_upload_threads()
    except KeyboardInterrupt:
        logger.info("interrupted")
        g.kill_threads()
