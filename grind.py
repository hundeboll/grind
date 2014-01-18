#!/usr/bin/env python2

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
import time
import pytz
import sys
import os

p = argparse.ArgumentParser(description='Upload new files to Google Drive')

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

class drive_push(object):
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

    backoff_time = 1
    stop = False
    done = 0
    https = []

    drive_index = {}
    drive_paths = {}
    drive_items = []
    drive_folders = {}
    drive_total_size = 0
    drive_upload_size = 0
    drive_upload_count = 0
    drive_update_size = 0
    drive_update_count = 0

    local_changed_files = {}
    local_new_files = {}
    local_meta_files = {}
    local_total_size = 0
    local_changed_size = 0
    local_new_size = 0
    local_unchanged_files = {}
    local_unchanged_size = 0

    def __init__(self, args):
        self.cred_path = args.credentials
        self.path = args.path + '/'
        self.threads = args.threads

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

    def update_progress(self):
        total_bytes = self.local_new_size + self.local_changed_size
        status_bytes = self.drive_upload_size
        total_count = len(self.local_new_files) + len(self.local_changed_files)
        status_count = self.drive_upload_count + self.drive_update_count
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
        count = len(self.local_new_files)
        size,unit = self.scale_bytes(self.local_new_size)
        logger.info('files new: {} ({} {})'.format(count, size, unit))

        count = len(self.local_changed_files)
        size,unit = self.scale_bytes(self.local_changed_size)
        logger.info('files changed: {} ({} {})'.format(count, size, unit))

        count = len(self.local_meta_files)
        logger.info('files meta changed: {}'.format(count))

        count = len(self.local_unchanged_files)
        size,unit = self.scale_bytes(self.local_unchanged_size)
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

    def local_md5sum(self, path, block_size=2**20):
        md5 = hashlib.md5()
        path = os.path.join(self.path, path)
        f = open(path, 'rb')

        while True:
            data = f.read(block_size)

            if not data:
                break

            md5.update(data)

        return md5.hexdigest()

    def drive_get_files(self):
        page_token = None

        while True:
            try:
                param = {'q': 'trashed=false',
                         'maxResults': 1000,
                         'fields': 'items(' + ','.join(self.fields) + '),nextPageToken'}
                logger.info("resolving drive files ({} files received)".format(len(self.drive_items)))

                if page_token:
                    param['pageToken'] = page_token

                files = self.drive.files().list(**param).execute()

                self.drive_items.extend(files['items'])
                page_token = files.get('nextPageToken')
                self.backoff_time = 0

                if not page_token:
                    break
            except errors.HttpError as e:
                logger.error("Failed to receive file list from drive: {}".format(e))
                time.sleep(self.backoff_time)
                self.backoff_time *= 2

        logger.info('resolved {} files/folders'.format(len(self.drive_items)))

    def drive_build_tree(self):
        logger.info('building drive tree')

        for file_info in self.drive_items:
            self.drive_index[file_info['id']] = file_info

        for file_info in self.drive_items:
            title = file_info['title']

            if file_info['mimeType'] == 'application/vnd.google-apps.folder':
                if title in self.drive_folders:
                    logger.warning('duplicate folder name: ' + title)

                self.drive_folders[title] = file_info
                continue

            path = self.drive_recurse_tree(file_info)

            if path in self.drive_paths:
                logger.warning('duplicate file path: ' + path)

            self.drive_paths[path] = file_info
            self.drive_total_size += int(file_info.get('fileSize', 0))
            logger.debug("drive file: " + path)

    def drive_recurse_tree(self, file_info, path = None):
        if path:
            path = os.path.join(file_info['title'], path)
        else:
            path = file_info['title']

        if len(file_info['parents']) == 0:
            return path

        if file_info['parents'][0]['isRoot']:
            return path

        parent_id = file_info['parents'][0]['id']
        parent = self.drive_index[parent_id]

        return self.drive_recurse_tree(parent, path)

    def local_get_files(self):
        logger.info("resolving local files")

        for root, dirs, files in os.walk(self.path):
            files = [f for f in files if not f[0] == '.']
            dirs[:] = [d for d in dirs if not d[0] == '.']

            for f in files:
                path = os.path.join(root, f)
                path = path[len(self.path):]
                info = self.local_read_info(path)
                self.local_total_size += info['fileSize']

                if path not in self.drive_paths:
                    logger.debug("local new: " + path)
                    self.local_new_files[path] = info
                    self.local_new_size += info['fileSize']
                elif self.local_file_is_changed(path, info, checksum=True):
                    logger.debug("local changed: " + path)
                    self.local_changed_files[path] = info
                    self.local_changed_size += info['fileSize']
                elif self.local_file_is_changed(path, info, checksum=False):
                    logger.debug("local meta changed: " + path)
                    self.local_meta_files[path] = info
                else:
                    logger.debug("local unchanged: " + path)
                    self.local_unchanged_files[path] = info
                    self.local_unchanged_size += info['fileSize']

        self.local_new_files = sorted(self.local_new_files)
        self.local_changed_files = sorted(self.local_changed_files)

    def local_read_info(self, path):
        path = os.path.join(self.path, path)
        stats = os.stat(path)
        date = datetime.datetime.fromtimestamp(stats.st_ctime)
        date = date.replace(tzinfo=pytz.UTC)
        us = date.microsecond
        date = date.replace(microsecond=(us - (us % 1000)))

        return {'fileSize': stats.st_size,
                'modifiedDate': date}

    def local_file_is_changed(self, path, local_info, checksum=False):
        if path not in self.drive_paths:
            return True

        drive_info = self.drive_paths[path]
        drive_date = dateutil.parser.parse(drive_info['modifiedDate'])
        drive_size = int(drive_info['fileSize'])
        drive_md5 = drive_info['md5Checksum']

        local_date = local_info['modifiedDate']
        local_size = local_info['fileSize']

        if (local_date != drive_date or local_size != drive_size) and checksum:
            return drive_md5 != self.local_md5sum(path)

        if (local_date != drive_date or local_size != drive_size) and not checksum:
            return True

        return False

    def drive_create_folder(self, folder_name, parent_id = None):
        logger.debug('creating folder: ' + folder_name)
        body = {
                'title': folder_name,
                'mimeType': "application/vnd.google-apps.folder"
        }

        if parent_id:
            body['parents'] = [{'id': parent_id}]

        new_folder = self.drive.files().insert(body = body).execute()
        self.drive_folders[folder_name] = new_folder

        return new_folder['id']

    def drive_create_path(self, path):
        folders,filename = os.path.split(path)
        parent_id = None

        if not folders:
            return

        for folder in folders.split(os.sep):
            if folder not in self.drive_folders:
                parent_id = self.drive_create_folder(folder, parent_id)
            else:
                parent_id = self.drive_folders[folder]['id']

    def drive_create_paths(self):
        logger.info("creating directories")
        for path in self.local_new_files:
            self.drive_create_path(path)

    def drive_create_file(self, path, parent_id, drive=None):
        if not drive:
            drive = self.drive

        logger.debug('creating file: ' + path)
        date = self.local_read_info(path)['modifiedDate']
        date = date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        path = os.path.join(self.path, path)
        media_body = MediaFileUpload(path, resumable=True)

        body = {
                'title': os.path.basename(path),
                'modifiedDate': date,
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

        self.backoff_time = 0
        self.drive_upload_size += int(file_info['fileSize'])
        self.drive_upload_count += 1

    def drive_upload_file(self, path, drive=None):
        if not drive:
            drive = self.drive
        folder_path,file_name = os.path.split(path)

        if folder_path:
            folder_parent = os.path.basename(folder_path)
            folder_info = self.drive_folders[folder_parent]
            folder_id = folder_info['id']
        else:
            folder_id = None

        self.drive_create_file(path, folder_id, drive)

    def drive_upload_files(self, file_list=None, drive=None):
        logger.info("uploading new files")
        if not file_list:
            file_list = self.local_new_files

        if not drive:
            drive = self.drive

        for path in file_list:
            self.drive_upload_file(path, drive)
            if self.stop:
                break

        self.done += 1
        logger.debug("upload thread done")

    def drive_meta_update_file(self, path, drive=None):
        logger.debug("updating file meta: " + path)
        if not drive:
            drive = self.drive

        file_id = self.drive_paths[path]['id']
        date = self.local_read_info(path)['modifiedDate']
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

    def drive_meta_update_files(self, file_list=None, drive=None):
        logger.info("updating meta changed files")
        if not file_list:
            file_list = self.local_meta_files

        if not drive:
            drive = self.drive

        for path in file_list:
            self.drive_meta_update_file(path, drive)

        self.done += 1
        logger.debug("meta update thread done")

    def drive_update_file(self, path, drive=None):
        logger.debug("updating file: " + path)
        if not drive:
            drive = self.drive

        file_id = self.drive_paths[path]['id']
        date = self.local_read_info(path)['modifiedDate']
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

        self.backoff_time = 0
        self.drive_update_size += int(file_info['fileSize'])
        self.drive_update_count += 1

    def drive_update_files(self, file_list=None, drive=None):
        logger.info("updating changed files")
        if not file_list:
            file_list = self.local_changed_files

        if not drive:
            drive = self.drive

        for path in file_list:
            self.drive_update_file(path, drive)

        self.done += 1
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
        http = self.authorize()
        self.https.append(http)
        drive = self.create_drive(http)
        l = self.local_meta_files
        t = threading.Thread(target=self.drive_meta_update_files, args=[l, drive])
        t.start()
        self.threads += 1

    def start_update_thread(self):
        http = self.authorize()
        self.https.append(http)
        drive = self.create_drive(http)
        l = self.local_changed_files
        t = threading.Thread(target=self.drive_update_files, args=[l, drive])
        t.start()
        self.threads += 1

    def start_upload_threads(self):
        n = self.threads
        self.https = []

        for i in range(n):
            http = self.authorize()
            self.https.append(http)
            drive = self.create_drive(http)

            l = self.local_new_files[i::n]
            t = threading.Thread(target=self.drive_upload_files, args=[l, drive])
            t.start()
            self.threads += 1

        while self.done < self.threads:
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
        d = drive_push(args)
        d.drive_get_files()
        d.drive_build_tree()
        d.local_get_files()
        d.print_summary()

        if args.resolve:
            sys.exit(0)

        if not args.disable_meta:
            d.start_meta_update_thread()

        if not args.disable_update:
            d.start_update_thread()

        if not args.disable_upload:
            d.drive_create_paths()
            d.start_upload_threads()
    except KeyboardInterrupt:
        logger.info("interrupted")
        d.kill_threads()
