from __future__ import print_function

import googleapiclient.errors as gerr
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

# If modifying these scopes, delete the file token.json.
SCOPES = 'https://www.googleapis.com/auth/drive'

new_owner_id = None


def main():
    """Shows basic usage of the Drive v3 API.
    Prints the names and ids of the first 10 files the user has access to.
    """
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    store = file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('client_id.json', SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('drive', 'v3', http=creds.authorize(Http()))

    # Call the Drive v3 API
    results = service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print(u'{0} ({1})'.format(item['name'], item['id']))


def list_owners(service, folder_id):
    page_token = None

    response = service.files().list(q="trashed = false", # and '%s' in parents" % (folder_id,),
                                    spaces='drive',
                                    fields='nextPageToken, files(id, name)',
                                    pageToken=page_token).execute()

    for file in response.get('files', []):
        id = file.get('id')
        ownership = service.files().get(fileId=id, fields='owners').execute()['owners']
        # owner = resource['owners']
        print('File %s has is owned by %s' % (file.get('name'), ownership[0]['emailAddress']))


def grant_ownership(service, file_id, prefix, new_owner, show_already_owned):
    global new_owner_id

    resources = service.files().get(fileId=file_id, fields='name, owners').execute()
    full_path = prefix + "/" + resources['name']

    current_user_owns = False
    for owner in resources['owners']:
        if owner['emailAddress'] == new_owner:
            if show_already_owned:
                print('Item {} already has the right owner.'.format(full_path))
            return
        elif owner['me']:
            current_user_owns = True

    print('Item {} needs ownership transfer.'.format(full_path))

    if not current_user_owns:
        print('    But, current user does not own the item.'.format(full_path))
        return

    perms = service.permissions().list(fileId=file_id, fields='permissions(id, emailAddress)').execute()

    if new_owner_id is None:
        for item in perms['permissions']:
            if item.get('emailAddress') == new_owner:
                new_owner_id = item.get('id')
                break

    if new_owner_id:
        try:
            # permission = service.permissions().get(fileId=file_id, permissionId=new_owner_id).execute()
            # permission['role'] = 'owner'
            permission = {'role': 'owner'}
            print('    Upgrading existing permissions to ownership.')
            return service.permissions().update(fileId=file_id, permissionId=new_owner_id,
                                                body=permission, transferOwnership=True).execute()
        except gerr.HttpError as e:
            if e.resp.status != 404:
                print('An error occurred updating ownership permissions: {}'.format(e))
                return
    else:
        # print('    Creating new ownership permissions.')
        # permission = {'role': 'owner',
        #               'type': 'user',
        #               'id': new_owner_id}
        # try:
        #     service.permissions().insert(fileId=file_id, body=permission,
        #                                  emailMessage='Automated recursive transfer of ownership.').execute()
        # except gerr.HttpError as e:
        #     print('An error occurred inserting ownership permissions: {}'.format(e))
        print('    User does not have access to this file/folder, transfer failed.')


def process_all_files(service, new_owner, folder_id='root', prefix=None, verbose=False):
    if prefix is None:
        prefix = service.files().get(fileId=folder_id, fields='name').execute()['name']
        grant_ownership(service, folder_id, '', new_owner, verbose)

    if verbose:
        print('Now transferring folder {}...'.format(prefix))

    page_token = None
    while True:
        try:
            items = service.files().list(q="trashed = false and '%s' in parents" % (folder_id,),
                                         spaces='drive',
                                         fields='nextPageToken, files(id, name)',
                                         pageToken=page_token).execute()

            for item in items.get('files', []):
                id = item.get('id')
                ftype = service.files().get(fileId=id, fields='mimeType').execute()

                grant_ownership(service, id, prefix, new_owner, verbose)

                if ftype['mimeType'] == 'application/vnd.google-apps.folder':
                    new_prefix = prefix + '/' + item.get('name')
                    process_all_files(service, new_owner, folder_id=id, prefix=new_prefix, verbose=verbose)

            page_token = items.get('nextPageToken')
            if not page_token:
                break
        except gerr.HttpError as e:
            print('An error occurred: {}'.format(e))
            break

    if verbose:
        print('Ownership of folder {} has been transferred'.format(prefix))


if __name__ == '__main__':
    # main()

    store = file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('client_id.json', SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('drive', 'v3', http=creds.authorize(Http()))

    # list_owners(service, 'root')

    folder_id = '1TOGthj-PQfTD_zRBh1d6FAr3bRSSB_MV'
    new_owner = 'cssimps@stanford.edu'

    process_all_files(service, new_owner, folder_id=folder_id, verbose=True)
