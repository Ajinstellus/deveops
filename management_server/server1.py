import re
import urllib
import json
import pandas as pd
import pymongo
from aiohttp import web
import csv
import aiohttp_cors
import json
#import MangementSub
import requests
from pymongo import MongoClient
import glob
from datetime import datetime, date
from bson.objectid import ObjectId
from managementserver_basic import *
import logging.handlers as handlers
import logging

path_json = 'server-automobile.json'
with open(path_json) as json_file:
    server_details = json.load(json_file)

management_ip = server_details['management_ip']
management_path = server_details['management_path']
port = server_details['management_port']
mobile_server_location = server_details['mobile_server_location']
intrusion_snap_path = server_details['intrusion_snap_path']
program_name = server_details['program_name']
LOG_FILENAME = server_details['debug_log_name']
LOG_FILENAME_size = server_details['debug_log_size']
Node_run_port = server_details['Node_run_port']
Timeout = server_details['Timeout_registration']
sysPass = server_details['sysPass']
disk = server_details['disk']

mail_list = server_details['email_list']
sender = server_details['sender']
password = server_details['password']
subject = server_details['subject']
programsAlert = server_details['programs']
host = server_details['host']
mailport = server_details['mailport']

logger = logging.getLogger(program_name)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logHandler = handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=LOG_FILENAME_size, backupCount=1)
logHandler.setLevel(logging.INFO)
logger.addHandler(logHandler)
logHandler.setFormatter(formatter)

mongo_db = MongoClient('mongodb://cogxar:'+urllib.parse.quote("c0gTect@100")+'@'+management_ip+':27017/cubix-management')
login_db = mongo_db['cubix-management']
visitor_management = mongo_db['visitor-management']
mydb_notification = mongo_db.notificationDB
alertdata_db = mongo_db['alert']
criminalDB_general = mongo_db['criminalDB']
criminaldata_db = mongo_db['encode_v1']
management = mongo_db['automotive-management']
rtogui = mongo_db['RTOGUI']

# -----------register---------------
async def register(request):
    try:
        reg_data = await request.json()
        # logger.info(reg_data)
        users = management.users
        license_manager = management['license-manager']

        first_name = reg_data['first_name']
        last_name = reg_data['last_name']
        email = reg_data['email']
        password = reg_data['password']
        imei = reg_data['imei']
        mobileNumber = reg_data['mobilenumber']
        role = reg_data['role']
        department = reg_data['department']
        title = reg_data['title']
        verified = "NA"
        superadmin = reg_data['superadmin']
        created = datetime.utcnow()
        user_id = users.insert({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password,
            'role': role,
            'created': created,
            'department': department,
            'title': title,
            'license': '',
            'licenseRequest': '',
            'Imei': imei,
            'userId': '',
            'mobilenumber': mobileNumber,
            'verified': verified,
            'superadmin': superadmin
        })
        print(user_id)

        firstFive = str(user_id)[-5:]
        new_user = users.find_one({'_id': user_id})
        newvalues = {"$set": {"userId": first_name+firstFive}}
        if role == 'super-admin':
            newvalues = {"$set": {"userId": first_name + firstFive, "superadmin": first_name + firstFive}}

        users.update_one({'_id': user_id}, newvalues)

        if role == 'super-admin':
            license_row = {}
            license_row['user_id'] = first_name + firstFive
            license_row['programs'] = []
            license_row['users'] = 0
            license_row['portal_licence'] = ''
            license_row['device_license'] = ''
            license_row['portal_licence_file'] = ''
            license_row['device_license_file'] = ''
            license_row['portal_licence_status'] = ''
            license_row['device_license_status'] = ''
            license_row['device_license_data'] = {}
            license_row['camera_license_data'] = []

            _id = license_manager.insert(license_row)

        result = {'email': new_user['email'] + ' registered'}
        response_obj = {'result': result}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def login(request):
    users = management.users
    login_data = await request.json()
    print("________________________")
    print(login_data)
    email = login_data['email']
    password = login_data['password']
    device_id = login_data['device_id']
    result = ""
    response = users.find_one({'email': email})
    print("response", response)
    if response:
        if response['password'] == password:
            out = {}
            out['first_name'] = response['first_name']
            out['last_name'] = response['last_name']
            out['email'] = response['email']
            out['role'] = response['role']
            out['title'] = response['title']
            out['department'] = response['department']
            out['license'] = response['license']
            out['licenseRequest'] = response['licenseRequest']
            out['verified'] = response['verified']
            out['userId'] = response['userId']
            out['superadmin'] = response['superadmin']

            if 'device_id' not in response.keys():
                new_device_id = {"$set": {'device_id': device_id}}
                new_user = users.find_one({'_id': response['_id']})
                users.update_one({'_id': response['_id'], }, new_device_id)
                print("new_user", new_user)
                response_obj = out
            elif response['device_id'] == device_id:
                print("successfully logged in")
                response_obj = out
            else:
                response_obj = {"error": "1"}
        else:
            response_obj = {"error": "2"}
    else:
        response_obj = {"error": "3"}

    print(response_obj)
    return web.json_response(response_obj)


if __name__ == '__main__':
    head, tail = os.path.split(__file__)
    filename = os.path.splitext(tail)[0]
    app = web.Application(client_max_size=server_details['client_max'] ** 2)
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })

    cors.add(app.router.add_post('/users/register', register))
    cors.add(app.router.add_post('/users/login', login))

    web.run_app(app, port=port)
