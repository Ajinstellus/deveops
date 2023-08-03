import re
import urllib
import json

import pandas as pd
import pymongo
from aiohttp import web
import csv
import aiohttp_cors
import json
# import MangementSub
import requests
from pymongo import MongoClient
import glob
from datetime import datetime, date, timedelta
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
# mongo_db = MongoClient(management_ip , 27017)
mongo_db = MongoClient(
    'mongodb://cogxar:' + urllib.parse.quote("c0gTect@100") + '@' + management_ip + ':27017/cubix-management')
login_db = mongo_db['cubix-management']
visitor_management = mongo_db['visitor-management']
mydb_notification = mongo_db.notificationDB
alertdata_db = mongo_db['alert']
criminalDB_general = mongo_db['criminalDB']
criminaldata_db = mongo_db['encode_v1']
# management = mongo_db['cubix-management']
management = mongo_db['automotive-management']

rtogui = mongo_db['RTOGUI']


async def systemregistry(request):
    print("update sysytem status")
    try:
        user_data = await request.json()
        print(user_data)

        for key, value in user_data.items():
            key_ip = key
            client_ip = key_ip
            details = value
            details['ip'] = client_ip
            print(client_ip + "--" + details['DateTime'], details['userId'])
            # mongoDB update
            # print(datetime.now())
            details['DateTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            mycol = mydb_notification["sys-reg"]
            try:
                unique_client = mycol.find_one({"ip": client_ip}, {"_id": 0})
                print(unique_client)
                if unique_client:
                    id = {"ip": client_ip}
                    result = mycol.replace_one(id, details)
                    logger.info(" already exists")
                else:
                    mycol.insert_one(details)
                    logger.info(" not exists")
                cubix_mangement = mongo_db['automotive-management']
                camera = cubix_mangement['camera']
                query = {'deviceip': client_ip}
                query1 = {'userId': details['userId']}

                if camera.find({'$and': [query, query1]}):

                    details_cam_full = camera.find({'$and': [query, query1]},
                                                   {'_id': 0, 'programhistory': 0, 'associate': 0, 'location': 0,
                                                    'devicename': 0,
                                                    'name': 0, 'datetime': 0, 'programs': 0, 'intrusioncanvas': 0,
                                                    'intrusionImageUrl': 0, 'dblist': 0})

                    res_cam = []
                    for details_cam in details_cam_full:

                        managment_program_path = os.path.join(management_path, 'program')
                        pr_name = details_cam['selectedprogram'] + '.zip'
                        program_folder = os.path.join(managment_program_path, pr_name)
                        if os.path.isfile(program_folder):
                            file_size = os.path.getsize(program_folder)
                            details_cam['filesize'] = file_size
                        else:
                            details_cam['filesize'] = 0
                        res_cam.append(details_cam)
                else:
                    res_cam = []
                print(res_cam)
                response_obj = res_cam
            except Exception as e:
                response_obj = {'status': 'false'}
            logger.info(response_obj)
            return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.Response(text=json.dumps(response_obj), status=500)


async def critical(request):
    try:
        # happy path where name is set
        user_data = await request.json()
        # print(user_data)
        text = user_data["DATA"]

        for line in text.split('@'):
            line_len = len(line)
            data_ctr = line.split(" ")
            if len(data_ctr) >= 6:
                current_message = data_ctr[5].split(":")[0]
                ip = data_ctr[2]
                json_build = {}
                json_build["ip"] = ip
                json_build["DateTime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                json_build["parentip"] = data_ctr[3]
                json_build["systemname"] = data_ctr[4]
                json_build["message"] = data_ctr[5].split(":")[0]
                json_build["value"] = data_ctr[5].split(":")[1]
                json_build["level"] = data_ctr[6]
                json_build["userId"] = user_data['userId']
                mycol = mydb_notification["critical"]
                unique_client = mycol.find_one({"$and": [{"ip": ip}, {"message": current_message}]})
                if unique_client:
                    logger.info("critical same")
                    mongo_id = unique_client.get('_id')
                    get_msg = unique_client['message']
                    logger.info(get_msg)
                    result = mycol.update_one({'_id': mongo_id}, {"$set": json_build}, upsert=False)
                else:
                    logger.info("critical diff")
                    mycol.insert(json_build)
        response_obj = {'status': "done"}
        return web.Response(text=json.dumps(response_obj), status=200)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.Response(text=json.dumps(response_obj), status=500)


async def event(request):
    try:
        # happy path where name is set
        user_data = await request.json()
        # print(user_data)
        text = user_data["DATA"]

        for line in text.split('@'):
            line_len = len(line)
            data_ctr_event = line.split(";")
            if len(data_ctr_event) >= 5:
                current_tasknumber = data_ctr_event[4]
                ip = data_ctr_event[1]
                json_build_event = {}
                json_build_event["ip"] = ip
                json_build_event["DateTime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                json_build_event["parentip"] = data_ctr_event[3]
                json_build_event["systemname"] = data_ctr_event[2]
                json_build_event["message"] = data_ctr_event[6]
                json_build_event["tasknumber"] = data_ctr_event[4]
                json_build_event["level"] = data_ctr_event[5]
                json_build_event["userId"] = user_data['userId']
                mycol = mydb_notification["event"]
                unique_client = mycol.find_one({"$and": [{"ip": ip}, {"tasknumber": current_tasknumber}]})
                if unique_client:
                    logger.info("event same")
                    if data_ctr_event[5] != "programlevel":
                        mongo_id = unique_client.get('_id')
                        get_msg = unique_client['message']
                        # logger.info(get_msg)
                        # message_get = get_msg.split(":")
                        # id = {"ip": ip}
                        # id2 = {"tasknumber": current_tasknumber}
                        result = mycol.update_one({'_id': mongo_id}, {"$set": json_build_event}, upsert=False)
                    else:
                        logger.info("event programlevel")
                        mycol.insert(json_build_event)
                else:
                    logger.info("event diff")
                    mycol.insert(json_build_event)
        response_obj = {'status': "done"}
        return web.Response(text=json.dumps(response_obj), status=200)
    except Exception as e:
        # Bad path where name is not set
        response_obj = {'status': 'failed', 'reason': str(e)}
        # return failed with a status code of 500 i.e. 'Server Error'
        return web.Response(text=json.dumps(response_obj), status=500)


async def alert_face_org(request):
    out_data = await request.json()
    name_alert = 'face'
    found_list = out_data['data']
    get_image(found_list, name_alert, management_path)

    if 'image_points' in found_list:
        del found_list['image_points']
    alert_face_array = []
    id = found_list['index']
    flag = 0
    if id != '':
        qu = {'_id': ObjectId(id)}

        list = criminaldata_db.collection_names()
        for x in list:
            doc = criminaldata_db[x]
            unique_client = doc.find_one(qu)
            if unique_client:
                details_cam = doc.find_one(qu)

                path_image = details_cam['path']

                description = details_cam['description']
                region = details_cam['region']
                flag = 1
                break
    else:
        flag = 1
        path_image = ''
        description = ''
        region = ''
    if flag == 1:
        found_list['path'] = path_image
        found_list['region'] = region
        found_list['description'] = description
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_face_array.append(found_list)

        name_doc = create_name_alert(name_alert, alertdata_db, logger)

        criminaldata_doc = alertdata_db[name_doc]

        try:
            if alert_face_array != []:
                criminaldata_doc.insert_many(alert_face_array)
                result = "updated"
            else:
                result = 'empty'
            response_obj = {'status': result}
            return web.Response(text=json.dumps(response_obj), status=200)
        except Exception as e:
            response_obj = {'status': 'failed', 'reason': str(e)}
            return web.Response(text=json.dumps(response_obj), status=500)
    else:
        response_obj = {'status': 'not found', 'reason': str(id)}
        return web.Response(text=json.dumps(response_obj), status=200)


async def alert_face(request):
    out_data = await request.json()

    # name_alert = 'face'
    found_list = out_data['data']

    if 'alert_name' in found_list:
        name_alert = found_list['alert_name']
        del found_list['alert_name']
    else:
        name_alert = 'face'

    print("alertname--- " + name_alert)

    id_mongo = found_list['id']
    # print('alert face--found_list',found_list['model_name'],id_mongo)
    flag = 0

    main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')

    full_path_snap = os.path.join(management_path, 'public', 'alert', name_alert)

    if id_mongo:
        qu = {'_id': ObjectId(id_mongo)}
        list_doc = criminaldata_db[found_list['model_name']]
        unique_client = list_doc.find_one(qu)
        if unique_client:
            details_cam = list_doc.find_one(qu)
            path_image1 = details_cam['path']

            name = ''
            region = ''
            description = ''
            gender = ''
            dob = ''
            type = ''

            file_name_base = os.path.basename(path_image1)
            path_image = os.path.join(main_path, file_name_base)

            imagename = found_list['frame_id'] + ".jpg"

            snap_full_path = os.path.join(full_path_snap, imagename)
            # print(snap_full_path)

            if os.path.isfile(snap_full_path):
                pass
            else:
                imagename = ""

            if 'type' in found_list:
                type = details_cam['type']
            else:
                type = ''

            if 'dob' in found_list:
                dob = details_cam['dob']
            else:
                dob = ''

            if 'gender' in found_list:
                gender = details_cam['gender']
            else:
                gender = ''

            if 'name' in found_list:
                name = details_cam['name']
            else:
                name = ''

            if 'description' in found_list:
                description = details_cam['description']
            else:
                description = ''
            if 'region' in found_list:
                region = details_cam['region']
            else:
                region = ''

            flag = 1
        else:
            print("no encode")
            print(out_data)
            flag = 1
            path_image = ''
            description = ''
            region = ''
            imagename = ""
    else:
        print("mongo id empty")
        flag = 1
        path_image = ''
        description = ''
        region = ''
        imagename = ""
    if flag == 1:
        found_list['name'] = name
        found_list['type'] = type
        found_list['dob'] = dob
        found_list['gender'] = gender

        found_list['path'] = path_image
        found_list['imagename'] = imagename
        found_list['region'] = region
        found_list['description'] = description
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        criminaldata_doc = alertdata_db[name_doc]
        try:
            if found_list:
                '''if 'id' in found_list:
                    del found_list['id']
                if 'model_name' in found_list:
                    del found_list['model_name']
                if 'roi' in found_list:
                    del found_list['roi']'''

                criminaldata_doc.insert_one(found_list)
                result = "updated"
            else:
                result = 'empty'
            response_obj = {'status': result}
        except Exception as e:
            response_obj = {'status': 'failed', 'reason': str(e)}
    else:
        response_obj = {'status': 'not found', 'reason': str(id)}
    return web.Response(text=json.dumps(response_obj), status=200)


async def alert_face_magnum(request):
    out_data = await request.json()
    # print(out_data)
    found_list = out_data['data']
    if 'alert_name' in found_list:
        name_alert = found_list['alert_name']
        del found_list['alert_name']
    else:
        name_alert = 'face'
    if 'jpg_as_text' in found_list:

        jpg_as_text = found_list['jpg_as_text']

        del found_list['jpg_as_text']

        print(found_list)

        name = found_list['frame_id'] + ".jpg"

        nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
        img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        full_path = os.path.join(management_path, 'public', 'alert', name_alert)
        if os.path.isdir(full_path):
            pass
        else:
            os.makedirs(full_path)
        name_path = os.path.join(full_path, name)
        # print(name_path)
        cv2.imwrite(name_path, img_final)
        result = "success"

    id_mongo = found_list['id']

    flag = 0

    main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')

    full_path_snap = os.path.join(management_path, 'public', 'alert', name_alert)

    if id_mongo:
        qu = {'_id': ObjectId(id_mongo)}

        criminaldata_magnum = mongo_db['encode_magnum']

        list_doc = criminaldata_magnum['database']
        unique_client = list_doc.find_one(qu)
        if unique_client:
            details_cam = list_doc.find_one(qu)
            path_image1 = details_cam['path']

            file_name_base = os.path.basename(path_image1)

            print('alert face--found_list', id_mongo, file_name_base)

            path_image = os.path.join(main_path, file_name_base)

            imagename = found_list['frame_id'] + ".jpg"

            snap_full_path = os.path.join(full_path_snap, imagename)
            # print(snap_full_path)

            if os.path.isfile(snap_full_path):
                pass
            else:
                imagename = ""

            if 'description' in found_list:
                description = details_cam['description']
            else:
                description = ''
            if 'region' in found_list:
                region = details_cam['region']
            else:
                region = ''

            flag = 1
        else:
            print("no encode")
            print(out_data)
            flag = 1
            path_image = ''
            description = ''
            region = ''
            imagename = ""
    else:
        print("mongo id empty")
        flag = 1
        path_image = ''
        description = ''
        region = ''
        imagename = ""
    if flag == 1:
        found_list['path'] = path_image
        found_list['imagename'] = imagename
        found_list['region'] = region
        found_list['description'] = description
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        criminaldata_doc = alertdata_db[name_doc]
        try:
            if found_list:
                '''if 'id' in found_list:
                    del found_list['id']
                if 'model_name' in found_list:
                    del found_list['model_name']
                if 'roi' in found_list:
                    del found_list['roi']'''

                criminaldata_doc.insert_one(found_list)
                result = "updated"
            else:
                result = 'empty'
            response_obj = {'status': result}
        except Exception as e:
            response_obj = {'status': 'failed', 'reason': str(e)}
    else:
        response_obj = {'status': 'not found', 'reason': str(id)}
    return web.Response(text=json.dumps(response_obj), status=200)


async def updation_done(request):
    data = await request.json()
    print(data)
    print("_______________________________________ent")
    print("updation_done", data['name'], data['selectedprogram'])

    try:
        cam_list = management['camera']
        if data['name'] == "encodeupdate":
            print('encodeupdate state change')
            st_encode = data['update_status']
            update = {'status': st_encode}
            out_con = cam_list.update_one({
                '$and': [

                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update}, upsert=False)

            print(out_con.raw_result)

            '''if 'programname' in data:
                if data['programname'] == 'face':
                    update_list = {'dblist': []}
                    cam_list.update_one({
                        '$and': [
                            {'deviceip': data['device_ip']},
                            {'cameraip': data['cameraip']},
                            {'cameraname': data['cameraname']},
                            {'userId': data['userId']}
                        ]
                    }, {"$set": update_list}, upsert=False)'''
            response_obj = {'status': 'updated'}

        elif data['name'] == 'analyse-status':
            analysestatus = data['update_status']
            update = {'analyse-status': analysestatus}
            print(update)
            out_con = cam_list.update_one({
                '$and': [

                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update}, upsert=False)

            print(out_con.raw_result)

            response_obj = {'status': 'updated'}

        elif data['name'] == 'analyse-status':
            analysestatus = data['update_status']
            update = {'analyse-status': analysestatus}
            print(update)
            out_con = cam_list.update_one({
                '$and': [

                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update}, upsert=False)

            print(out_con.raw_result)

            response_obj = {'status': 'updated'}

        elif data['name'] == 'ss':

            update_ss = {'ss': '0'}
            print(update_ss)
            out_con = cam_list.update_one({
                '$and': [

                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update_ss}, upsert=False)

            print(out_con.raw_result)

            response_obj = {'status': 'updated'}

        elif data['name'] == 'programstatus':
            logger.info('programstatus')
            st = data['programstatus']
            update = {'programstatus': st}
            cam_list.update_one({'deviceip': data['device_ip']}, {"$set": update}, upsert=False)
            response_obj = {'status': 'updated'}
        elif data['name'] == 'runningstatus':
            logger.info('runningstatus')
            st = data['programrunstatus']
            update = {'runningstatus': st}

            print("programrunstatus", update)

            output = cam_list.update_one({
                '$and': [

                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update}, upsert=False)
            print(output.modified_count, output.raw_result)

            response_obj = {'status': 'updated'}
        elif data['name'] == 'history':

            logger.info('enter history')
            add_name = data['history']
            ip_query = {'deviceip': data['device_ip']}
            out = cam_list.find_one(ip_query)
            x = out['programhistory']
            array_his = []
            if len(x) != 0:
                if add_name in x:
                    logger.info('true')
                else:
                    logger.info('new update')
                    x.append(add_name)
                    x.remove("")
                    update = {'programhistory': x}
                    cam_list.update_one(ip_query, {"$set": update}, upsert=False)
            else:
                array_his.append(add_name)
                array_his.remove("")
                logger.info('new update')
                update = {'programhistory': array_his}
                cam_list.update_one(ip_query, {"$set": update}, upsert=False)

            response_obj = {'status': 'updated'}
        elif data['name'] == "message":
            logger.info('update message')
            st_encode = data['programrunstatus']
            update = {'message': st_encode}
            cam_list.update_one({
                '$and': [
                    # {'deviceip': data['device_ip']},
                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']},
                    {'selectedprogram': data['selectedprogram']}
                ]
            }, {"$set": update}, upsert=False)
            response_obj = {'status': 'updated'}
        else:
            result = "not updated"
            response_obj = {'status': result}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        print(response_obj)
        return web.json_response(response_obj)


async def program_config(request):
    print("progrm config")
    out_data = await request.json()
    print(out_data)

    camera = management['camera']
    # print(out_data)
    client_ip = out_data['ip']
    cameraip = out_data['cameraip']
    cameraname = out_data['cameraname']
    userId = out_data['userId']

    # query = {'deviceip': client_ip}
    query1 = {'cameraip': cameraip}
    query2 = {'cameraname': cameraname}
    query3 = {'userId': userId}
    query = {'selectedprogram': out_data['selectedprogram']}

    print(query1, query2, query3, query)
    details_cam = camera.find_one({'$and': [query1, query2, query3, query]},
                                  {'_id': 0, 'programhistory': 0, 'associate': 0, 'location': 0, 'devicename': 0,
                                   'name': 0, 'datetime': 0, 'programs': 0, 'intrusioncanvas': 0,
                                   'intrusionImageUrl': 0, 'templeteImage': 0})

    print(details_cam)
    return web.json_response(details_cam)


async def program_config_mulity(request):
    print("progrm config")
    out_data = await request.json()

    camera = management['camera']
    # print(out_data)
    client_ip = out_data['ip']
    cameraip = out_data['cameraip']
    # cameraname = out_data['cameraname']
    userId = out_data['userId']

    query = {'deviceip': client_ip}
    query1 = {'cameraip': cameraip}
    # query2 = {'cameraname': cameraname}
    query3 = {'userId': userId}
    print(query, query1, query3)
    details_cam = camera.find({'$and': [query, query1, query3]},
                              {'_id': 0, 'programhistory': 0, 'associate': 0, 'location': 0, 'devicename': 0,
                               'name': 0, 'datetime': 0, 'programs': 0, 'intrusioncanvas': 0, 'intrusionImageUrl': 0,
                               'templeteImage': 0})

    cam_list = []
    for cam in details_cam:
        cam_list.append(cam)

    print(cam_list)
    return web.json_response(cam_list)


camera = management['camera']


async def get_sys_reg(request):
    out_data = await request.json()

    userId = out_data['userId']

    try:
        logger.info("enter")
        sys_db = mydb_notification["sys-reg"]
        # logger.info(sys_db)
        cursor = sys_db.find({"userId": userId}, {'_id': False})
        # logger.info(cursor.size)
        full_data = []
        for document in cursor:
            details = {}
            the_time = datetime.now()
            current_datetime = the_time.replace(second=0, microsecond=0)
            node_time = datetime.strptime(document['DateTime'], "%Y-%m-%d %H:%M:%S")
            node_time = node_time.replace(second=0, microsecond=0)
            difference_time = current_datetime - node_time
            if (difference_time.seconds / 60) > 2:
                node_status = "Offline"
            else:
                node_status = "Online"

            details['IP'] = document['ip']
            details['CPU Usage'] = document['CPUC']
            details['Disk Usage'] = document['DISKUSG']
            details['Memory Usage'] = document['MEMC']
            details['Date Time'] = document['DateTime']
            details['Runstatus'] = document['RUNSTATUS']
            details['Parent ip'] = document['parentip']
            details['System Temperature'] = document['Temperature']
            details['Node Status'] = node_status
            details['License'] = document['License']
            clientstat = {}
            if 'dockerStatus' in document:
                clientstat = document['dockerStatus']
                for lc in clientstat:
                    clientId = lc['CONTAINER ID']
                    del lc['CONTAINER ID']
                    del lc['BLOCK I/O']
                    del lc['PIDS']
                    del lc['NAME']
                    query = {"hostName": clientId}
                    print(query)
                    details_cam = camera.find_one(query, )
                    print(details_cam)
                    if details_cam:
                        lc['cameraname'] = details_cam['cameraname']
                    else:
                        lc['cameraname'] = ''
                print(clientstat)
            finallist = {}
            finallist["server"] = details
            finallist["client"] = clientstat
            full_data.append(finallist)
        return web.json_response(full_data)
    except Exception as e:
        # Bad path where name is not set
        response_obj = {'status': 'failed', 'reason': str(e)}
        # return failed with a status code of 500 i.e. 'Server Error'
        return web.json_response(response_obj)


async def getSysregByIp(request):
    # try:
    logger.info("enter")
    out_data = await request.json()
    ip = out_data['ip']
    userId = out_data['userId']
    sys_db = mydb_notification["sys-reg"]
    # logger.info(sys_db)
    print(userId, ip)
    myquery = {"$and": [{'userId': userId}, {'ip': ip}]}
    cursor = sys_db.find(myquery)
    # logger.info(cursor.size)
    full_data = []
    for document in cursor:
        # print(document)
        details = {}
        the_time = datetime.now()
        current_datetime = the_time.replace(second=0, microsecond=0)

        node_time = datetime.strptime(document['DateTime'], "%Y-%m-%d %H:%M:%S")
        node_time = node_time.replace(second=0, microsecond=0)

        difference_time = current_datetime - node_time
        # print(difference_time.seconds / 60 )
        if (difference_time.seconds / 60) > 2:
            node_status = "Offline"
        else:
            node_status = "Online"

        details['IP'] = document['ip']
        details['CPU Usage'] = document['CPUC']
        details['Disk Usage'] = document['DISKUSG']
        details['Memory Usage'] = document['MEMC']
        details['Date Time'] = document['DateTime']
        details['Runstatus'] = document['RUNSTATUS']
        details['Parent ip'] = document['parentip']
        details['System Temperature'] = document['Temperature']
        details['Node Status'] = node_status
        details['License'] = document['License']
        full_data.append(details)

    # print(full_data)
    return web.json_response(full_data)


async def get_event(request):
    try:
        logger.info("enter")
        out_data = await request.json()
        userId = out_data['userId']
        sys_db = mydb_notification["event"]
        cursor_event = sys_db.find({"userId": userId})
        # logger.info(cursor.size)
        full_data_event = []
        i = 0
        for document_event in cursor_event:
            details_event = {}
            # logger.info(document)

            details_event['IP'] = document_event['ip']
            details_event['Message'] = document_event['message']
            details_event['Tasknumber'] = document_event['tasknumber']
            details_event['Parentip'] = document_event['parentip']
            details_event['Date Time'] = document_event['DateTime']
            full_data_event.append(details_event)
        return web.json_response(full_data_event)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def get_critical(request):
    out_data = await request.json()
    userId = out_data['userId']
    try:
        # logger.info("enter_critical")
        sys_db = mydb_notification["critical"]

        cursor_ctl = sys_db.find({"userId": userId})
        # logger.info(cursor.size)
        full_data_ctl = []
        i = 0
        for document_ctl in cursor_ctl:
            details_critical = {}
            # logger.info(document)
            ip_ctl = document_ctl['ip']
            details_critical['IP'] = document_ctl['ip']
            details_critical['Message'] = document_ctl['message'] + "-" + document_ctl['value']
            details_critical['Date Time'] = document_ctl['DateTime']
            details_critical['Parentip'] = document_ctl['parentip']
            full_data_ctl.append(details_critical)

        return web.json_response(full_data_ctl)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getFaceAlertsByName(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        userid = out_data['userId']
        name = out_data['name']
        print(name)

        documentName = userid + "_" + program
        name_face = get_name(documentName, mongo_db)
        alertdata_db = mongo_db['alert']
        print('2')
        sys_db_face = alertdata_db[name_face]
        # logger.info(name_face)

        regexval = ".*" + name
        query = {"path": {"$regex": regexval}}
        cursor_face = sys_db_face.find(query)
        print(cursor_face)
        full_data_face = []
        for document_face in cursor_face:
            id_obj = str(ObjectId(document_face['_id']))

            if '_id' in document_face:
                del document_face['_id']

            document_face['id'] = id_obj
            full_data_face.append(document_face)
        print(len(full_data_face))
        return web.json_response(full_data_face)
    except Exception as e:
        print(e)
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getFaceAlerts(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        userId = out_data['userId']
        print(program)

        document_name = userId + "_" + program
        name_face = get_name(document_name, mongo_db)
        print('1')
        alertdata_db = mongo_db['alert']
        print('2')
        sys_db_face = alertdata_db[name_face]
        # logger.info(name_face)

        startYear = out_data['startYear']
        startMonth = out_data['startMonth']
        startDate = out_data['startDate']
        endYear = out_data['endYear']
        endMonth = out_data['endMonth']
        endDate = out_data['endDate']
        print(startYear)

        sdate = date(startYear, startMonth, startDate)  # start date
        edate = date(endYear, endMonth, endDate)  # end date
        delta = edate - sdate  # as timedelta
        full_data_face = []
        for i in range(delta.days + 1):
            day = sdate + timedelta(days=i)
            print(day)
            regexval = str(day) + "/*"
            query = {"datetime": {"$regex": regexval}}
            cursor_face = sys_db_face.find(query)
            print(cursor_face)
            for document_face in cursor_face:
                id_obj = str(ObjectId(document_face['_id']))

                if '_id' in document_face:
                    del document_face['_id']

                document_face['id'] = id_obj
                full_data_face.append(document_face)
        print(len(full_data_face))
        return web.json_response(full_data_face)
    except Exception as e:
        print(e)
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsLatest(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        cameraName = out_data['cameraName']
        count = out_data['count']
        deptCameras = out_data['deptCameras']

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:

            print(program)
            cam_arr = deptCameras.split(',')

            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            query = {}
            if (cameraName == ""):
                if (deptCameras == ''):
                    query = {}
                else:
                    query = {"cameraname": {"$in": cam_arr}}
            else:
                query = {"$and": [{"cameraname": cameraName}]}
            print(query)
            if name_face:
                alertdata_db = mongo_db['alert']
                sys_db_face = alertdata_db[name_face]
                # logger.info(name_face)
                cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING).limit(count)
                # logger.info(cursor.size)

                for document_face in cursor_face:
                    id_obj = str(ObjectId(document_face['_id']))

                    if '_id' in document_face:
                        del document_face['_id']

                    document_face['id'] = id_obj
                    full_data_face.append(document_face)

        dates = full_data_face
        # dates.sort(key=lambda date: datetime.strptime(date, '%Y-%m-%d %H:%M::S'))
        dates.sort(key=lambda x: datetime.strptime(x['datetime'],
                                                   '%Y-%m-%d %H:%M:%S'))
        # dates.sort(key=lambda date: datetime.strptime(date, '%d %b %Y'))

        return web.json_response(dates)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getVehicleDataByNumber(request):
    reg_data = await request.json()
    number = reg_data['number']
    print(number)
    vehicle_col = management['vehicle-data']
    # logger.info(name_face)
    cursor_face = vehicle_col.find({"vehiclenumber": number})
    # logger.info(cursor.size)
    full_data_face = []

    for document_face in cursor_face:
        id_obj = str(ObjectId(document_face['_id']))

        if '_id' in document_face:
            del document_face['_id']

        document_face['id'] = id_obj
        print(json.dumps(document_face, default=str))
        full_data_face.append(json.dumps(document_face, default=str))

    return web.json_response(full_data_face)


async def getVehicleData(request):
    vehicle_col = management['vehicle-data']
    # logger.info(name_face)
    cursor_face = vehicle_col.find()
    # logger.info(cursor.size)
    full_data_face = []

    for document_face in cursor_face:
        id_obj = str(ObjectId(document_face['_id']))

        if '_id' in document_face:
            del document_face['_id']

        document_face['id'] = id_obj
        print(json.dumps(document_face, default=str))
        full_data_face.append(json.dumps(document_face, default=str))

    return web.json_response(full_data_face)


async def updateVehicle(request):
    reg_data = await request.json()
    number = reg_data['number']
    print(number)

    ownerName = reg_data['ownerName']
    print(ownerName)

    empId = reg_data['empId']
    phNumber = reg_data['phNumber']
    email = reg_data['email']

    vehicletype = reg_data['vehicletype']


    vehicle_col = management['vehicle-data']
    vehicle = vehicle_col.find_one({"vehiclenumber": number})

    if vehicle:
        print("Already cameraip exists")
        myquery = {"$and": [{"vehiclenumber": number}]}
        newvalues = {"$set": {"ownername": ownerName,

                              "emp_id": empId,
                              "phonenumber": phNumber,
                              "email": email,

                              "vehicletype": vehicletype}}


        vehicle_col.update_one(myquery, newvalues)
        isUpdated = "updated"
    else:
        row = {}
        row['vehiclenumber'] = number
        row['ownername'] = ownerName

        row['emp_id'] = empId
        row['phonenumber'] = phNumber
        row['email'] = email

        row['vehicletype'] = vehicletype

        row['insertdate'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        isUpdated = "added"

        _id = vehicle_col.insert(row)
        print(_id)
    response_obj = {'status': isUpdated}
    return web.json_response(response_obj)


async def updateVehicleExcel(request):
    try:
        print("updateVehicleExcel")
        vehicle = management['vehicle-data']
        content = await request.json()
        print(content["file"])
        csvfile = open(content["file"])
        filepath = content["file"]
        userId = content['userId']
        superadmin = content['superadmin']
        reader = csv.DictReader(csvfile)
        isUpdated = "notupdated"
        header = ["emp_id", "vehicletype", "vehiclenumber", "ownername","phonenumber", "email"]

        wb = xlrd.open_workbook(filepath)
        sh = wb.sheet_by_name('Sheet1')
        for rownum in range(sh.nrows):
            print(sh.row_values(rownum))
            row = sh.row_values(rownum)
            row1 = {}
            if (rownum > 0):
                vehicledata = vehicle.find_one({"$and": [
                    {"vehiclenumber": row[1]}, {"userId": userId}]})
                if vehicledata:
                    # logger.info("Already cameraip exists")
                    isUpdated = "exists"
                else:
                    for column in range(len(row)):
                        print(column)
                        print(header[column])
                        print(row[column])
                        row1[header[column]] = str(row[column])

                    row1["create_at"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print(row1)
                    _id = vehicle.insert(row1)
                    print(_id)
                    isUpdated = "updated"

        response_obj = {'status': isUpdated}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


def getlistusers(userId):
    userdata = management['users']

    finddata = userdata.find({"superadmin": userId})
    listofuser = []
    for document in finddata:
        listofuser.append(document['userId'])
    return listofuser


async def getAlerts(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        print(program)
        listuser = getlistusers(superuserId)
        print("listofuser", listuser)
        full_data_face = []
        for userId in listuser:

            name_list = userId + "_" + program

            name_face = get_name(name_list, mongo_db)

            if name_face:
                alertdata_db = mongo_db['alert']
                sys_db_face = alertdata_db[name_face]
                # logger.info(name_face)
                cursor_face = sys_db_face.find({})
                # logger.info(cursor.size)

                for document_face in cursor_face:
                    id_obj = str(ObjectId(document_face['_id']))

                    if '_id' in document_face:
                        del document_face['_id']

                    document_face['id'] = id_obj
                    full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getUsersByDepartment(request):
    try:
        users_db = management['users']
        camera_db = management['camera']
        out_data = await request.json()
        userId = out_data['userId']
        department = out_data['department']

        query = {"$and": [{"department": department}]}
        users = users_db.find(query)
        user_list = []
        for user in users:
            print(user)
            user_list.append(user['userId'])
        print(user_list)
        result = camera_db.find({"userId": {"$in": user_list}})

        print(result)
        full_data_face = []
        for camera in result:
            print(camera)
            full_data_face.append(camera['cameraname'])

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsLatestAlpr(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        cameraName = out_data['cameraName']
        count = out_data['count']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')

        listuser = getlistusers(superuserId)

        vehicle_col = management["vehicle-data"]
        full_data_face = []
        for userId in listuser:
            name_list = userId + "_" + program
            name_face = get_name(name_list, mongo_db)

            query = {}
            if (cameraName == ""):
                if (deptCameras == ''):
                    query = {}
                else:
                    query = {"cameraname": {"$in": cam_arr}}

            else:
                query = {"$and": [{"cameraname": cameraName}]}

            if name_face:
                alertdata_db = mongo_db['alert']
                sys_db_face = alertdata_db[name_face]

                alpr_alerts = sys_db_face.find(query).sort('_id', pymongo.DESCENDING).limit(count)
                alpr_vehicle = list(vehicle_col.find({}))
                for alert_alpr in alpr_alerts:
                    print(alert_alpr['message'])
                    print('---------------')
                    id_obj = str(ObjectId(alert_alpr['_id']))
                    if '_id' in alert_alpr:
                        del alert_alpr['_id']

                    alert_alpr['id'] = id_obj
                    alert_alpr["exist"] = "false"
                    for vehicle in alpr_vehicle:
                        print(alert_alpr['message'] + " == " + vehicle['vehiclenumber'])
                        if (alert_alpr['message'] == vehicle['vehiclenumber'].replace("-", "")):
                            print("whitelist")
                            alert_alpr["exist"] = "true"

                    full_data_face.append(alert_alpr)
        dates = full_data_face
        # dates.sort(key=lambda date: datetime.strptime(date, '%Y-%m-%d %H:%M::S'))
        dates.sort(key=lambda x: datetime.strptime(x['datetime'],
                                                   '%Y-%m-%d %H:%M:%S'))
        # dates.sort(key=lambda date: datetime.strptime(date, '%d %b %Y'))

        return web.json_response(dates)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsLatestAlprByCamera(request):
    print("getAlertsLatestAlprByCamera")
    out_data = await request.json()
    program = out_data['program']
    userId = out_data['userId']
    cameraName = out_data['cameraname']
    date = out_data['date']
    print(program)

    vehicle_col = management["vehicle-data"]
    name_list = userId + "_" + program
    print(name_list)
    name_face = get_name(name_list, mongo_db)
    print(name_face)

    regexval = date + "/*"
    query = {}
    if (cameraName == ""):
        query = {"datetime": {"$regex": regexval}}
    else:
        query = {"$and": [{"datetime": {"$regex": regexval}, "cameraname": cameraName}]}
    full_data_face = []
    if name_face:
        alertdata_db = mongo_db['alert']

        collection_count = name_face.split("_")[2]
        for n in range(int(collection_count), 0, -1):
            if name_face:

                alert_col_name = name_list + "_" + str(n)
                sys_db_face = alertdata_db[alert_col_name]
                alpr_alerts = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                alpr_vehicle = list(vehicle_col.find({}))
                for alert_alpr in alpr_alerts:
                    id_obj = str(ObjectId(alert_alpr['_id']))
                    if '_id' in alert_alpr:
                        del alert_alpr['_id']

                    alert_alpr['id'] = id_obj
                    alert_alpr["exist"] = "false"
                    for vehicle in alpr_vehicle:
                        # print(alert_alpr['message'] + " == " + vehicle['vehiclenumber'])
                        if (alert_alpr['message'] == vehicle['vehiclenumber'].replace("-", "")):
                            print("whitelist")
                            alert_alpr["exist"] = "true"
                            break

                    full_data_face.append(alert_alpr)



    else:
        full_data_face = []

    return web.json_response(full_data_face)


async def getAlertById(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        userId = out_data['userId']
        alertId = out_data['alertId']
        print(program)
        name_list = userId + "_" + program
        print(name_list)
        name_face = get_name(name_list, mongo_db)
        print(name_face)
        if name_face:
            alertdata_db = mongo_db['alert']
            sys_db_face = alertdata_db[name_face]
            query = {'_id': ObjectId(alertId)}
            cursor_face = sys_db_face.find(query)
            # logger.info(cursor.size)
            full_data_face = []

            for document_face in cursor_face:
                id_obj = str(ObjectId(document_face['_id']))

                if '_id' in document_face:
                    del document_face['_id']

                document_face['id'] = id_obj
                full_data_face.append(document_face)
        else:
            full_data_face = []

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsByDate(request):
    print('--- getAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        date = out_data['date']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            if (name_face):
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        regexval = date + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                query = {"datetime": {"$regex": regexval}}
                            else:
                                query = {"datetime": {"$regex": regexval}, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": regexval}, "cameraname": cameraname}
                        print(query)
                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getMaskAlertsByDate(request):
    print('--- getMaskAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        # regexval = date + "/*"
                        # if(cameraname == ''):
                        #     if (deptCameras == ''):
                        #         query = {"datetime": {"$regex": regexval}}
                        #     else:
                        #         query = {"datetime": {"$regex": regexval}, "cameraname": {"$in": cam_arr}}
                        # else:
                        #     query = {"datetime": {"$regex": regexval}, "cameraname": cameraname}
                        # print(query)
                        # query = {"datetime": {"$regex": regexval}}
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                            # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}

                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getPpeAlertsByDate(request):
    print('--- getPpeAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        # regexval = date + "/*"
                        # if(cameraname == ''):
                        #     if (deptCameras == ''):
                        #         query = {"datetime": {"$regex": regexval}}
                        #     else:
                        #         query = {"datetime": {"$regex": regexval}, "cameraname": {"$in": cam_arr}}
                        # else:
                        #     query = {"datetime": {"$regex": regexval}, "cameraname": cameraname}
                        # print(query)
                        # query = {"datetime": {"$regex": regexval}}
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                            # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}

                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        logger.info(cursor_face)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            print("inside for 3")
                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getProdAlertsByDate(request):
    print('--- getProdAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        # regexval = date + "/*"
                        # if(cameraname == ''):
                        #     if (deptCameras == ''):
                        #         query = {"datetime": {"$regex": regexval}}
                        #     else:
                        #         query = {"datetime": {"$regex": regexval}, "cameraname": {"$in": cam_arr}}
                        # else:
                        #     query = {"datetime": {"$regex": regexval}, "cameraname": cameraname}
                        # print(query)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):

                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            box_obj = document_face['message'][:5]
                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['Box'] = box_obj

                            full_data_face.append(document_face)

        df = pd.DataFrame(list(full_data_face))
        # print(full_data_face)

        # print(df)
        df = df.sort_values(by=['cameraname', 'datetime'])

        new_df = df[df.Tag == 'missingtime']
        new_df = new_df.sort_values(by=['cameraname', 'Box', 'datetime'])
        new_df['timeval'] = new_df['message'].str[6:len(new_df['message'])]
        new_df['ftime'] = new_df.timeval.str.split('to').str[0]
        new_df['ftime'] = new_df.ftime.str.strip()
        new_df['ftime'] = pd.to_datetime(new_df['ftime'], format='%Y-%m-%d %H:%M:%S')
        new_df['ttime'] = new_df.timeval.str.split('to').str[1]
        new_df['ttime'] = new_df.ttime.str.strip()
        new_df['ttime'] = pd.to_datetime(new_df['ttime'], format='%Y-%m-%d %H:%M:%S')
        new_df['tottime'] = new_df['ttime'] - new_df['ftime']
        new_df['tottime'] = new_df['tottime'].dt.seconds / 3600

        summary = new_df.groupby(['cameraname', 'Box']).agg(
            {'tottime': "sum"}).reset_index()  # return web.json_response(full_data_face)
        summary = summary.sort_values(by=['cameraname'])

        summary = summary.to_dict('records')
        print(summary)
        return web.json_response(summary)
    except Exception as e:
        print('status is failed', 'reason', str(e))
        # response_obj = {'status': 'failed', 'reason': str(e)}
        response_obj = []
        return web.json_response(response_obj)


async def getProdAlertsBySummary(request):
    print('--- getProdAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        # regexval = date + "/*"
                        # if(cameraname == ''):
                        #     if (deptCameras == ''):
                        #         query = {"datetime": {"$regex": regexval}}
                        #     else:
                        #         query = {"datetime": {"$regex": regexval}, "cameraname": {"$in": cam_arr}}
                        # else:
                        #     query = {"datetime": {"$regex": regexval}, "cameraname": cameraname}
                        # print(query)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):

                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            box_obj = document_face['message'][:5]
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['Box'] = box_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            full_data_face.append(document_face)

        df = pd.DataFrame(list(full_data_face))
        # print(full_data_face)

        # print(df)
        df = df.sort_values(by=['cameraname', 'datetime'])

        new_df = df[df.Tag == 'missingtime']

        # new_df['Box'] = new_df['message'].str[:5]
        new_df = new_df.sort_values(by=['cameraname', 'Box', 'datetime'])

        new_df['timeval'] = new_df['message'].str[6:len(new_df['message'])]
        new_df['ftime'] = new_df.timeval.str.split('to').str[0]
        new_df['ftime'] = new_df.ftime.str.strip()
        new_df['ftime'] = pd.to_datetime(new_df['ftime'], format='%Y-%m-%d %H:%M:%S')
        new_df['ttime'] = new_df.timeval.str.split('to').str[1]
        new_df['ttime'] = new_df.ttime.str.strip()
        new_df['ttime'] = pd.to_datetime(new_df['ttime'], format='%Y-%m-%d %H:%M:%S')
        new_df['tottime'] = new_df['ttime'] - new_df['ftime']
        new_df['tottime'] = new_df['tottime'].dt.seconds / 3600

        summary = new_df.groupby(['datetime', 'cameraname', 'Box']).agg(
            {'tottime': "sum"}).reset_index()  # return web.json_response(full_data_face)
        # summary = summary.sort_values(by=['datetime','cameraname','Box'], ascending=[False])
        summary['tottime'] = summary['tottime'].apply(lambda x: 0 if x > 24 else round(24 - x, 2))
        summary = summary.to_dict('records')
        print(summary)
        return web.json_response(summary)
    except Exception as e:
        print('status is failed', 'reason', str(e))
        # response_obj = {'status': 'failed', 'reason': str(e)}
        response_obj = []
        return web.json_response(response_obj)


async def getqueueAlertsByDate(request):
    print('--- getqueueAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            if (name_face):
                collection_count = name_face.split("_")[2]
                print("I am")
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)
                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], 'a%Y-%m-%d %H:%M:%S')
                            msg_obj = document_face['message']
                            cnt_msg = msg_obj.count(":")
                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            if cnt_msg == 1:
                                document_face['message1'] = msg_obj.split(':')[0]
                                document_face['message2'] = int(msg_obj.split(':')[1])
                                full_data_face.append(document_face)
                            else:
                                print("check")

            df = pd.DataFrame(list(full_data_face))
            print(df)
            summary = df.groupby(['datetime']).agg(
                {'message2': "sum"}).reset_index()  # return web.json_response(full_data_face)
            # summary= summary.sort_values(by=['datetime'], ascending=[False])

            # summary = summary.head().to_dict('records')
            print(summary)
        return web.json_response(summary)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getqueueAlertsBySummary(request):
    print('--- getqueueAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            if (name_face):
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)
                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')
                            msg_obj = document_face['message']
                            cnt_msg = msg_obj.count(":")
                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            if cnt_msg == 1:
                                document_face['message1'] = msg_obj.split(':')[0]
                                document_face['message2'] = int(msg_obj.split(':')[1])
                                full_data_face.append(document_face)
                            else:
                                print("check")

            df = pd.DataFrame(list(full_data_face))
            summary = df.groupby(['datetime', 'cameraname']).agg(
                {'message2': "sum"}).reset_index()  # return web.json_response(full_data_face)
            summary = summary.sort_values(by=['datetime', 'cameraname'])

            summary = summary.to_dict('records')
            print(summary)
        return web.json_response(summary)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getCapAlertsByDate(request):
    print('--- getCapAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            if (name_face):
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)
                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')
                            msg_obj = document_face['message']
                            cnt_msg = msg_obj.count(":")
                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            full_data_face.append(document_face)

            df = pd.DataFrame(list(full_data_face))
            summary = df.groupby(['datetime']).agg(
                {'message': "count"}).reset_index()  # return web.json_response(full_data_face)
            summary = summary.sort_values(by=['datetime'], ascending=[False])

            print(summary)
            summary = summary.head().to_dict('records')

        return web.json_response(summary)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getPeopleAlertsByDate(request):
    print('--- getPeopleAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):

                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')
                            msg_obj = document_face['message']
                            msg_obj1 = msg_obj.split(',')[0]
                            msg_obj2 = msg_obj.split(',')[1]

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            # document_face['message1'] = msg_obj1.split(':')[0]
                            document_face['Enter'] = msg_obj1.split(':')[1]
                            # document_face['message3'] = msg_obj2.split(':')[0]
                            document_face['Exit'] = msg_obj2.split(':')[1]

                            full_data_face.append(document_face)
            # full_data_face_1 = full_data_face['datetime','cameraname','Enter','Exit']
        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getPeopleAlertsBySummary(request):
    print('--- getPeopleAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):

                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')
                            msg_obj = document_face['message']
                            msg_obj1 = msg_obj.split(',')[0]
                            msg_obj2 = msg_obj.split(',')[1]

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            # document_face['message1'] = msg_obj1.split(':')[0]
                            document_face['Enter'] = msg_obj1.split(':')[1]
                            # document_face['message3'] = msg_obj2.split(':')[0]
                            document_face['Exit'] = msg_obj2.split(':')[1]

                            full_data_face.append(document_face)
                # full_data_face_1 = full_data_face['datetime','cameraname','Enter','Exit']
                df = pd.DataFrame(list(full_data_face))
                # summary = df.groupby(['datetime']).agg(enter_sum = ('Enter', 'sum'),exit_sum = ('Exit', 'sum')).reset_index()  # return web.json_response(full_data_face)
                # summary = df.groupby(['datetime'])[['Enter','Exit']].sum()
                summary = df.groupby(['datetime'])[["Enter", "Exit"]].apply(lambda x: x.astype(int).sum()).reset_index()
                summary = summary.sort_values(by=['datetime'], ascending=[False])

                summary = summary.to_dict('records')
                print(summary)
            return web.json_response(summary)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAnalyticsAlertsBySummary(request):
    print('--- getPeopleAlertsByDate ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')
        print(program)
        print(date)

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print("Namelist", name_list)
            name_face = get_name(name_list, mongo_db)
            print("name face", name_face)
            print("I am here")
            if (name_face):
                print("entered if")
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        print("I am here 2")
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        print(alert_col_name)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):

                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)

                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))
                            date_obj = datetime.strptime(document_face['datetime'], '%Y-%m-%d %H:%M:%S')
                            # msg_obj = document_face['message']
                            # msg_obj1= msg_obj.split(',')[0]
                            # msg_obj2= msg_obj.split(',')[1]

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            document_face['datetime'] = date_obj.strftime('%Y/%m/%d')
                            # document_face['message1'] = msg_obj1.split(':')[0]
                            # document_face['Enter'] = msg_obj1.split(':')[1]
                            # document_face['message3'] = msg_obj2.split(':')[0]
                            # document_face['Exit'] = msg_obj2.split(':')[1]

                            full_data_face.append(document_face)
                # full_data_face_1 = full_data_face['datetime','cameraname','Enter','Exit']
                df = pd.DataFrame(list(full_data_face))
                # summary = df.groupby(['datetime']).agg(enter_sum = ('Enter', 'sum'),exit_sum = ('Exit', 'sum')).reset_index()  # return web.json_response(full_data_face)
                # summary = df.groupby(['datetime'])[['Enter','Exit']].sum()
                summary = df.groupby(['datetime'])[['message']].apply(lambda x: x.count()).reset_index()
                summary = summary.sort_values(by=['datetime'], ascending=[False])

                summary = summary.to_dict('records')
                print(summary)
            return web.json_response(summary)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsBetweenDates(request):
    print('--- getAlertsBetweenDates ---')
    try:
        out_data = await request.json()
        program = out_data['program']
        superuserId = out_data['userId']
        startdate = out_data['startdate']
        enddate = out_data['enddate']
        cameraname = out_data['cameraname']
        deptCameras = out_data['deptCameras']
        cam_arr = deptCameras.split(',')

        listuser = getlistusers(superuserId)
        print("listofuser*******", listuser)

        full_data_face = []

        for userId in listuser:
            name_list = userId + "_" + program
            print(name_list)
            name_face = get_name(name_list, mongo_db)
            print(name_face)

            if (name_face):
                collection_count = name_face.split("_")[2]
                for n in range(int(collection_count), 0, -1):
                    if name_face:
                        alertdata_db = mongo_db['alert']
                        alert_col_name = name_list + "_" + str(n)
                        sys_db_face = alertdata_db[alert_col_name]
                        # logger.info(name_face)
                        startregexval = startdate + "/*"
                        endregexval = enddate + "/*"
                        if (cameraname == ''):
                            if (deptCameras == ''):
                                # query = {"datetime": {"$regex": regexval}}
                                query = {
                                    "$expr": {
                                        "$and": [
                                            {
                                                "$gte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        startdate + " 00:00:00",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            },
                                            {
                                                "$lte": [
                                                    {"$dateFromString": {"dateString": "$datetime",
                                                                         "format": "%Y-%m-%d %H:%M:%S"}},
                                                    datetime.strptime(
                                                        enddate + " 23:59:59",
                                                        '%Y-%m-%d %H:%M:%S')
                                                ]
                                            }
                                        ]
                                    }
                                }
                                # query = {"datetime": {"$regex": startregexval}}

                            else:
                                # query = {"datetime": {"$regex": startregexval}, "cameraname": {"$in": cam_arr}}
                                query = {"$expr": {
                                    "$and": [
                                        {
                                            "$gte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    startdate + " 00:00:00",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        },
                                        {
                                            "$lte": [
                                                {"$dateFromString": {"dateString": "$datetime",
                                                                     "format": "%Y-%m-%d %H:%M:%S"}},
                                                datetime.strptime(
                                                    enddate + " 23:59:59",
                                                    '%Y-%m-%d %H:%M:%S')
                                            ]
                                        }
                                    ]
                                }, "cameraname": {"$in": cam_arr}}
                        else:
                            query = {"datetime": {"$regex": startregexval}, "cameraname": cameraname}
                        print(query)
                        cursor_face = sys_db_face.find(query).sort('_id', pymongo.DESCENDING)
                        # logger.info(cursor.size)

                        for document_face in cursor_face:
                            id_obj = str(ObjectId(document_face['_id']))

                            if '_id' in document_face:
                                del document_face['_id']

                            document_face['id'] = id_obj
                            full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlertsByMonth(request):
    try:
        out_data = await request.json()
        program = out_data['program']
        userId = out_data['userId']
        month = out_data['month']
        print(program)
        print(month)

        name_list = userId + "_" + program
        print(name_list)
        name_face = get_name(name_list, mongo_db)
        print(name_face)
        if name_face:
            alertdata_db = mongo_db['alert']
            sys_db_face = alertdata_db[name_face]
            # logger.info(name_face)
            regexval = "^" + month + "^"
            print(regexval)
            query = {"datetime": {"$regex": regexval}}
            cursor_face = sys_db_face.find()
            # logger.info(cursor.size)
            full_data_face = []

            for document_face in cursor_face:
                id_obj = str(ObjectId(document_face['_id']))

                if '_id' in document_face:
                    del document_face['_id']

                document_face['id'] = id_obj

                datetime = document_face['datetime']
                month_alert = datetime.split('-')[1]
                print(month)
                if month == month_alert:
                    full_data_face.append(document_face)

        else:
            full_data_face = []

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def alert_demo(request):
    res = await request.json()
    print('alert_demo')
    found_list = res['data']
    alert_name = found_list['alert_name']
    print("alert _________________________________________________________")
    print(found_list['userId'], found_list['alert_name'])
    name_alert = found_list['userId'] + "_" + found_list['alert_name']
    if 'analyse-status' in found_list:
        analysestatus = found_list['analyse-status']
        print('analysestatus', analysestatus)
    if 'store_maxvalues' in found_list:
        store_maxvalues = found_list['store_maxvalues']
        print('store_maxvalues', store_maxvalues)
        print(type(store_maxvalues))
    if 'alert_name' in found_list:
        del found_list['alert_name']
    if 'jpg_as_text' in found_list:
        get_image(found_list, name_alert, management_path)
    if 'jpg_as_text' in found_list:
        del found_list['jpg_as_text']
    found_list['notified'] = 'NA'
    found_list['verified'] = 'NA'
    found_list['piTime'] = found_list['datetime']
    found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    last_updated_name = get_coll_name(name_alert, alertdata_db)
    name_doc = create_name_alert(name_alert, alertdata_db, logger)
    criminaldata_doc = alertdata_db[name_doc]
    try:
        logger.info("enter")
        out_res = criminaldata_doc.insert_one(found_list)
        updated_id = out_res.inserted_id
        cam_list = management['program-config']
        print("alert _________________________________________________________")
        update = {"alertId": str(ObjectId(updated_id))}
        print(update)
        ip_query = {'program': alert_name}
        print(ip_query)
        out_con = cam_list.update_one(ip_query, {"$set": update}, upsert=False)
        print(out_con.raw_result)
        result = "updated"
        response_obj = {'result': result}
        # return web.Response(text=json.dumps(response_obj), status=200)
    except Exception as e:
        print(e)
        response_obj = {'result': 'failed', 'reason': str(e)}
    return web.Response(text=json.dumps(response_obj), status=500)


async def alertOffline(request):
    out_data = await request.json()

    print(out_data)

    found_list = out_data['data']
    name_program = found_list['alert_name']
    analysestatus = False
    store_maxvalues = False

    if name_program != 'face':
        name_alert = found_list['userId'] + "_" + found_list['alert_name']
        if 'analyse-status' in found_list:
            analysestatus = found_list['analyse-status']
            print('analysestatus', analysestatus)
        if 'store_maxvalues' in found_list:
            store_maxvalues = found_list['store_maxvalues']
            print('store_maxvalues', store_maxvalues)
            print(type(store_maxvalues))
        if 'alert_name' in found_list:
            del found_list['alert_name']
        if 'jpg_as_text' in found_list:
            get_image(found_list, name_alert, management_path)
        if 'jpg_as_text' in found_list:
            del found_list['jpg_as_text']
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['piTime'] = found_list['datetime']
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_updated_name = get_coll_name(name_alert, alertdata_db)
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        criminaldata_doc = alertdata_db[name_doc]
        try:
            logger.info("enter")
            out_res = criminaldata_doc.insert_one(found_list)
            updated_id = out_res.inserted_id
            cam_list = management['camera']
            update = {"analysed-alert": str(ObjectId(updated_id))}
            print(update)

            if analysestatus:
                print('analysestatus', analysestatus)

                out_con = cam_list.update_one({
                    '$and': [
                        {'deviceip': found_list['deviceip']},
                        {'cameraip': found_list['cameraip']},
                        {'cameraname': found_list['cameraname']},
                        {'userId': found_list['userId']}
                    ]
                }, {"$set": update}, upsert=False)

                print(out_con)

            if store_maxvalues:
                update_maxvalues = {"maxHash": found_list['maxHash'], "maxScore": found_list['maxScore']}

                out_con_re = cam_list.update_one({
                    '$and': [
                        {'deviceip': found_list['deviceip']},
                        {'cameraip': found_list['cameraip']},
                        {'cameraname': found_list['cameraname']},
                        {'userId': found_list['userId']}
                    ]
                }, {"$set": update_maxvalues}, upsert=False)

                print(out_con_re)

            result = "updated"
            response_obj = {'result': result}
            return web.Response(text=json.dumps(response_obj), status=200)
        except Exception as e:
            print(e)
            response_obj = {'result': 'failed', 'reason': str(e)}
    else:
        print('________________________________________________________________________')
        print("enter_alert alertOffline face")
        updateres = False
        path_image = ''
        description = ''
        region = ''
        imagename = ""
        found_list = out_data['data']
        if 'analyse-status' in found_list:
            analysestatus = found_list['analyse-status']
        if 'alert_name' in found_list:
            name_alert_in = found_list['alert_name']
            del found_list['alert_name']
        else:
            name_alert_in = 'face'
        name_alert = found_list['userId'] + "_" + name_alert_in
        print(name_alert)
        if 'jpg_as_text' in found_list:
            jpg_as_text = found_list['jpg_as_text']
            del found_list['jpg_as_text']
            name = found_list['frame_id'] + ".jpg"
            nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
            img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            full_path = os.path.join(management_path, 'public', 'alert', name_alert)
            if os.path.isdir(full_path):
                pass
            else:
                os.makedirs(full_path)
            name_path = os.path.join(full_path, name)
            cv2.imwrite(name_path, img_final)
        id_mongo = found_list['id']
        print(id_mongo)
        main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')
        full_path_snap = os.path.join(management_path, 'public', 'alert', name_alert)
        if id_mongo:
            qu = {'_id': ObjectId(id_mongo)}
            userId = found_list['userId']
            db_list_name = userId + "_encode"
            list_doc = criminalDB_general[db_list_name]
            unique_client = list_doc.find_one(qu)

            # print(unique_client)

            if unique_client:
                details_cam = list_doc.find_one(qu)
                path_image1 = details_cam['path']
                file_name_base = os.path.basename(path_image1)
                # print('alert face--found_list', found_list['model_name'], id_mongo, file_name_base)
                path_image = os.path.join(main_path, file_name_base)
                imagename = found_list['frame_id'] + ".jpg"
                snap_full_path = os.path.join(full_path_snap, imagename)
                if os.path.isfile(snap_full_path):
                    pass
                else:
                    imagename = ""
                if 'description' in found_list:
                    description = details_cam['description']
                else:
                    description = ''
                if 'region' in found_list:
                    region = details_cam['region']
                else:
                    region = ''
        found_list['path'] = path_image
        found_list['imagename'] = imagename
        found_list['region'] = region
        found_list['description'] = description
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['piTime'] = found_list['datetime']
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # print(found_list)
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        # print(name_doc)
        criminaldata_doc = alertdata_db[name_doc]
        try:
            if found_list:
                out_res = criminaldata_doc.insert_one(found_list)

                updateres = out_res.acknowledged

                result = "updated"
            else:
                result = 'empty'
            response_obj = {'status': result, "acknowledged": updateres}
        except Exception as e:
            print(e)
            response_obj = {'status': 'failed', 'reason': str(e), "acknowledged": False}

        print(response_obj)
    return web.Response(text=json.dumps(response_obj))


def send_mail2(program, cameraname, message):
    url = server_details['mailurl']

    new_json = {
        "program": program,
        "cameraname": cameraname,
        "message": message
    }

    try:
        r = requests.post(url, data=json.dumps(new_json), timeout=server_details['timeoutMailserver'])
        print("status", r.status_code)
        print(r.json())
        out = "updated"
    except Exception as e:
        print('*************************** send_mail', e)

    '''
    if program in programsAlert:
        for addr in mail_list:

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = addr
            # msg['To'] = 'komala@cogxar.com'
            msg['Subject'] = program + " " + subject
            body = "Alert for " + program + '\n' + "camera: " + cameraname + '\n' + "Message: " + message
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP(host, mailport)
            server.starttls()
            server.login(sender, password)
            text = msg.as_string()
            server.sendmail(sender, addr, text)
            server.quit()

            print(addr,'done')
    '''


async def alert_general_peoplecount(request):
    print("_________________________________________ alert_general_peoplecount")
    out_data = await request.json()
    # print(out_data)

    if "data" in out_data:
        found_list = out_data['data']
    else:
        found_list = out_data
    # found_list = out_data
    name_program = found_list['alert_name']

    send_mail2(name_program, found_list['cameraname'], found_list['message'])
    print('________________________________________________________________________ alert_general_peoplecount')
    print("enter_alert", name_program)

    name_alert = found_list['userId'] + "_" + found_list['alert_name']

    if 'alert_name' in found_list:
        del found_list['alert_name']
    if 'jpg_as_text' in found_list:
        get_image(found_list, name_alert, management_path)
    if 'jpg_as_text' in found_list:
        del found_list['jpg_as_text']
    found_list['notified'] = 'NA'
    found_list['verified'] = 'NA'
    found_list['piTime'] = found_list['datetime']
    found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    last_updated_name = get_coll_name(name_alert, alertdata_db)
    name_doc = create_name_alert(name_alert, alertdata_db, logger)
    criminaldata_doc = alertdata_db[name_doc]

    out_con = criminaldata_doc.update_one({
        '$and': [
            {'cameraip': found_list['cameraip']},
            {'cameraname': found_list['cameraname']},
            {'userId': found_list['userId']}, {'date': found_list['date']}
        ]
    }, {"$set": found_list}, upsert=False)

    if out_con.raw_result['updatedExisting']:
        print("------------------ Existing count update ")
    else:
        out_res = criminaldata_doc.insert_one(found_list)
        print(out_res.acknowledged, "new count")
    result = "updated"
    response_obj = {'result': result}
    return web.Response(text=json.dumps(response_obj), status=200)


async def alert_general(request):
    print("_________________________________________ alert_general")
    out_data = await request.json()
    # print(out_data)

    if "data" in out_data:
        found_list = out_data['data']
    else:
        found_list = out_data
    # found_list = out_data
    name_program = found_list['alert_name']
    analysestatus = False
    store_maxvalues = False
    send_mail2(name_program, found_list['cameraname'], found_list['message'])
    print('________________________________________________________________________ alert')
    print("enter_alert", name_program)
    if name_program != 'face':
        name_alert = found_list['userId'] + "_" + found_list['alert_name']
        if 'analyse-status' in found_list:
            analysestatus = found_list['analyse-status']
            print('analysestatus', analysestatus)
        if 'store_maxvalues' in found_list:
            store_maxvalues = found_list['store_maxvalues']

        if 'alert_name' in found_list:
            del found_list['alert_name']
        if 'jpg_as_text' in found_list:
            get_image(found_list, name_alert, management_path)
        if 'jpg_as_text' in found_list:
            del found_list['jpg_as_text']
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['piTime'] = found_list['datetime']
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_updated_name = get_coll_name(name_alert, alertdata_db)
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        criminaldata_doc = alertdata_db[name_doc]

        if 'update' in found_list:
            if found_list['update'] == 'true':

                fullalert = criminaldata_doc.find({'$and': [
                    {'cameraip': found_list['cameraip']},
                    {'cameraname': found_list['cameraname']},
                    {'userId': found_list['userId']}
                ]},
                    {'update': 0, 'verified': 0, 'notified': 0})
                flgcount = []
                for xda in fullalert:
                    dateFormat = "%Y-%m-%d %H:%M:%S"
                    # print(found_list['piTime'],xda['piTime'])
                    diffReset = datetime.strptime(found_list['piTime'], dateFormat) - datetime.strptime(xda['piTime'],
                                                                                                        dateFormat)
                    if diffReset.days != 0:

                        flgcount.append(False)
                    else:
                        flgcount.append(True)
                #####print(flgcount)
                if True in flgcount:
                    updateflag = True
                else:
                    updateflag = False

            else:
                updateflag = False
        else:
            updateflag = False
        print('updateflag alert', updateflag)
        if updateflag:
            out_con = criminaldata_doc.update_one({
                '$and': [
                    {'cameraip': found_list['cameraip']},
                    {'cameraname': found_list['cameraname']},
                    {'userId': found_list['userId']}
                ]
            }, {"$set": found_list}, upsert=False)

            # print("update res",out_con.raw_result['updatedExisting'])
            if out_con.raw_result['updatedExisting']:
                pass
            else:
                out_res = criminaldata_doc.insert_one(found_list)
            result = "updated"
            response_obj = {'result': result}
            return web.Response(text=json.dumps(response_obj), status=200)

        else:

            try:
                logger.info("enter")
                out_res = criminaldata_doc.insert_one(found_list)
                updated_id = out_res.inserted_id
                cam_list = management['camera']
                update = {"analysed-alert": str(ObjectId(updated_id))}
                print(update)

                if analysestatus:
                    print('analysestatus', analysestatus)

                    out_con = cam_list.update_one({
                        '$and': [
                            {'deviceip': found_list['deviceip']},
                            {'cameraip': found_list['cameraip']},
                            {'cameraname': found_list['cameraname']},
                            {'userId': found_list['userId']}
                        ]
                    }, {"$set": update}, upsert=False)

                    print(out_con)

                if store_maxvalues:
                    update_maxvalues = {"maxHash": found_list['maxHash'], "maxScore": found_list['maxScore']}

                    out_con_re = cam_list.update_one({
                        '$and': [
                            {'deviceip': found_list['deviceip']},
                            {'cameraip': found_list['cameraip']},
                            {'cameraname': found_list['cameraname']},
                            {'userId': found_list['userId']}
                        ]
                    }, {"$set": update_maxvalues}, upsert=False)

                    print(out_con_re)

                result = "updated"
                response_obj = {'result': result}
                return web.Response(text=json.dumps(response_obj), status=200)
            except Exception as e:
                print("error alert", e)
                response_obj = {'result': 'failed', 'reason': str(e)}
    else:
        updateres = False
        path_image = ''
        description = ''
        region = ''
        imagename = ""
        # found_list = out_data['data']
        if 'analyse-status' in found_list:
            analysestatus = found_list['analyse-status']
        if 'alert_name' in found_list:
            name_alert_in = found_list['alert_name']
            del found_list['alert_name']
        else:
            name_alert_in = 'face'
        name_alert = found_list['userId'] + "_" + name_alert_in
        if 'jpg_as_text' in found_list:
            jpg_as_text = found_list['jpg_as_text']
            del found_list['jpg_as_text']
            name = found_list['frame_id'] + ".jpg"
            nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
            img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            full_path = os.path.join(management_path, 'public', 'alert', name_alert)
            if os.path.isdir(full_path):
                pass
            else:
                os.makedirs(full_path)
            name_path = os.path.join(full_path, name)
            print(name_path)
            cv2.imwrite(name_path, img_final)

        id_mongo = found_list['id']
        main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')
        full_path_snap = os.path.join(management_path, 'public', 'alert', name_alert)
        imagename = found_list['frame_id'] + ".jpg"
        print(imagename)
        snap_full_path = os.path.join(full_path_snap, imagename)
        if os.path.isfile(snap_full_path):
            pass
        else:
            imagename = ""

        name = ""
        type = ""
        dob = ""
        gender = ""
        if id_mongo and id_mongo != "Unknown":
            qu = {'_id': ObjectId(id_mongo)}
            userId = found_list['userId']
            db_list_name = userId + "_encode"
            list_doc = criminalDB_general[db_list_name]
            unique_client = list_doc.find_one(qu)
            if unique_client:
                details_cam = list_doc.find_one(qu)
                path_image1 = details_cam['path']
                file_name_base = os.path.basename(path_image1)
                print('alert face--found_list', id_mongo, file_name_base)
                path_image = os.path.join(main_path, file_name_base)

                if 'type' in details_cam:
                    type = details_cam['type']
                else:
                    type = ''

                if 'dob' in details_cam:
                    dob = details_cam['dob']
                else:
                    bob = ''

                if 'gender' in details_cam:
                    gender = details_cam['gender']
                else:
                    gender = ''

                if 'name' in details_cam:
                    name = details_cam['name']
                else:
                    name = ''

                if 'description' in details_cam:
                    description = details_cam['description']
                else:
                    description = ''
                if 'region' in details_cam:
                    region = details_cam['region']
                else:
                    region = ''

        found_list['name'] = name
        found_list['type'] = type
        found_list['dob'] = dob
        found_list['gender'] = gender
        found_list['path'] = path_image
        found_list['imagename'] = imagename
        found_list['region'] = region
        found_list['description'] = description
        found_list['notified'] = 'NA'
        found_list['verified'] = 'NA'
        found_list['piTime'] = found_list['datetime']
        found_list['datetime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name_doc = create_name_alert(name_alert, alertdata_db, logger)
        criminaldata_doc = alertdata_db[name_doc]
        try:
            if found_list:
                print(found_list)
                out_res = criminaldata_doc.insert_one(found_list)
                updateres = out_res.acknowledged
                if analysestatus:
                    updated_id = out_res.inserted_id

                    cam_list = management['camera']

                    update = {"analysed-alert": updated_id}

                    out_con = cam_list.update_one({
                        '$and': [
                            {'deviceip': found_list['deviceip']},
                            {'cameraip': found_list['cameraip']},
                            {'cameraname': found_list['cameraname']},
                            {'userId': found_list['userId']}
                        ]
                    }, {"$set": update}, upsert=False)

                result = "updated"
            else:
                result = 'empty'
            response_obj = {'status': result, "acknowledged": updateres}
        except Exception as e:
            print("alerterror", e)
            response_obj = {'status': 'failed', 'reason': str(e), "acknowledged": False}

    return web.Response(text=json.dumps(response_obj))


async def getAlertsCanvas(request):
    try:
        out_data = await request.post()
        program = out_data['program']
        userId = out_data['userId']
        count = out_data['count']
        print(program)
        documentName = userId + "_" + program
        name_face = get_name(documentName, mongo_db)
        print('1')
        alertdata_db = mongo_db['alert']
        print('2')
        sys_db_face = alertdata_db[name_face]
        # logger.info(name_face)
        cursor_face = sys_db_face.find({"verified": "NA"}).sort('_id', pymongo.DESCENDING).limit(int(count))
        # logger.info(cursor.size)
        full_data_face = []

        for document_face in cursor_face:
            id_obj = str(ObjectId(document_face['_id']))

            if '_id' in document_face:
                del document_face['_id']

            document_face['id'] = id_obj
            full_data_face.append(document_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateVerifiedAlert(request):
    try:
        reg_data = await request.post()
        verifyId = reg_data['verifyId']
        program = reg_data['program']
        userId = reg_data['userId']
        print(program, 'ver')
        print(verifyId)

        documentName = userId + "_" + program
        name_face = get_name(documentName, mongo_db)
        alertdata_db = mongo_db['alert']
        sys_db_face = alertdata_db[name_face]
        # logger.info(name_face)
        myquery = {'_id': ObjectId(verifyId)}
        newvalues = {"$set": {"verified": "yes"}}
        sys_db_face.update_one(myquery, newvalues)

        response_obj = {'status': 'updated'}

        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def get_encode_list_general(request):
    data = await request.json()
    userId = data['userId']

    cr_db_list_name = userId + "_encode"

    try:
        criminaldata_list_magnum = criminalDB_general[cr_db_list_name]
        out_data = {}
        print('encode len', criminaldata_list_magnum.count())
        data_encode = []
        for x in criminaldata_list_magnum.find():
            if "employeeID" in x:
                emid = x['employeeID']
            else:
                emid = ''
            d = [{"index": str(ObjectId(x['_id'])), "encoding": x['encoding'], "name": x['name'], "employeeID": emid}]
            data_encode.extend(d)
        logger.info("management get encode ")
    except Exception as e:
        data_encode = []

    build_encode_json = {}
    build_encode_json["encode"] = data_encode
    return web.Response(text=json.dumps(build_encode_json), status=200)


async def get_criminaldb_count(request):
    # criminaldb = criminaldata_db
    # criminaldb = mongo_db['criminalDB']
    input_data = await request.json()
    userId = input_data['userId']
    print(userId)
    list_db_name = userId + "_encode"
    print(list_db_name)
    list_deb_user = criminalDB_general[list_db_name]
    # list = list_deb_user.count()
    results = list_deb_user.find({"reference": "normal"})
    list = results.count()

    count = list

    return web.json_response({'count': count})


async def get_criminaldb(request):
    input_data = await request.json()
    print(input_data)
    startIndex = input_data['startIndex']
    endIndex = input_data['endIndex']
    userId = input_data['userId']
    list_db_name = userId + "_encode"
    print(list_db_name)
    list_deb_user = criminalDB_general[list_db_name]

    # list = criminaldata_db.collection_names()
    full_data_criminal = []
    count = 0
    main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')
    # cursor = list_deb_user.find({'reference': userId})
    cursor = list_deb_user.find({'reference': 'normal'})
    for document in cursor:
        # print(document)
        count += 1
        # print(str(count) + ' >= '+str(startIndex))
        if count >= startIndex and count <= endIndex:
            details = {}

            # details['Path'] = document['path']
            get_basename = os.path.basename(document['path'])
            details['Path'] = os.path.join(main_path, get_basename)

            details['name'] = document['name']
            if 'description' in document:
                details['description'] = document['description']
            else:
                details['description'] = ''

            if 'region' in document:
                details['region'] = document['region']
            else:
                details['region'] = ''
            details['id'] = str(ObjectId(document['_id']))
            full_data_criminal.append(details)

        if count > endIndex:
            break

    return web.json_response(full_data_criminal)


async def get_criminaldb_magnum(request):
    input_data = await request.json()
    print(input_data)
    startIndex = input_data['startIndex']
    endIndex = input_data['endIndex']
    criminaldata_magnum = mongo_db['encode_magnum']
    list = criminaldata_magnum.collection_names()
    full_data_criminal = []
    count = 0
    main_path = os.path.join(management_path, 'public', 'faceimages', 'faces')
    for list_name in list:
        cursor = criminaldata_magnum[list_name].find({})
        for document in cursor:
            count += 1
            if count >= startIndex and count <= endIndex:
                details = {}
                get_basename = os.path.basename(document['path'])
                details['Path'] = os.path.join(main_path, get_basename)
                details['name'] = document['name']
                if 'description' in document:
                    details['description'] = document['description']
                else:
                    details['description'] = ''
                if 'region' in document:
                    details['region'] = document['region']
                else:
                    details['region'] = ''
                details['id'] = str(ObjectId(document['_id']))
                full_data_criminal.append(details)

        if count > endIndex:
            break
    return web.json_response(full_data_criminal)


async def deletePlan(request):
    try:
        content = await request.json()
        floorPlan = management['zoned-floorplan']
        groups = management['groups']
        # id = ObjectId(content['id'])
        name = content['name']

        myquery = {"canvasName": name}
        x = floorPlan.delete_many(myquery)
        y = groups.delete_many(myquery)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def get_collections(request):
    try:
        input_data = await request.json()
        DB_name = input_data['DB_name']
        db = mongo_db[DB_name]
        collection_list = db.collection_names()
        json_collection_list = {}
        json_collection_list['result'] = collection_list
        return web.json_response(json_collection_list)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


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
        # password = bcrypt.hashpw(reg_data['password']).decode('utf-8')
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
        newvalues = {"$set": {"userId": first_name + firstFive}}
        if (role == 'super-admin'):
            newvalues = {"$set": {"userId": first_name + firstFive, "superadmin": first_name + firstFive}}

        users.update_one({'_id': user_id}, newvalues)

        if (role == 'super-admin'):
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

        response_obj = ({'result': result})
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
    print("responce", response)
    # console.log(response)
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

            # response_obj = out
            if 'device_id' not in response.keys():

                new_device_id = {"$set": {'device_id': device_id}}
                new_user = users.find_one({'_id': response['_id']})
                users.update_one({'_id': response['_id'], }, new_device_id)
                print("new_user", new_user)
                response_obj = out
            elif response['device_id'] == device_id:

                print("successfully logged in")
                # device id_present-user logged in other device
                # response_obj=({"error":"1"})
                response_obj = out
            else:
                response_obj = ({"error": "1"})

        else:
            # "Invalid username and password"
            response_obj = ({"error": "2"})
            # response_obj =({"error":"Invalid username and password"})
            # result = jsonify({"error": "Invalid username and password"})
    else:
        # "No results found"
        response_obj = ({"error": "3"})
        # response_obj = ({"error": "No results found"})
    # return result

    print(response_obj)
    return web.json_response(response_obj)


async def logout_mobile(request):
    users = management.users
    try:
        logout_data = await request.json()
        print("________________________")
        print(logout_data)
        userId = logout_data['userId']
        # password = login_data['password']
        device_id = logout_data['device_id']
        result = ""
        response = users.find_one({'userId': userId})
        print("responce", response)
        if response['userId'] == userId and response['device_id'] == device_id:
            print('condition true')
            users.update_one({'userId': userId}, {"$unset": {"device_id": 1}})
            print("userId", userId, "device_id", device_id)
        else:
            print('condition failed')
        # print("web",web.json_response(response))
        # return web.json_response(response)
        # response_obj=web.json_response(response)
        # print("response",response)
        # print("response_obj_1",response_obj)
        response_obj = {'status': 'successfull'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateLicenseRequest(request):
    try:
        logger.info('updateLicenseRequest')
        print('updateLicenseRequest')
        camera = management.camera
        reg_data = await request.json()
        cameraname = reg_data['cameraname']
        print(cameraname)
        # for record in cameraip:
        myquery = {"cameraname": cameraname}
        newvalues = {"$set": {"licenseRequest": "requested"}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateDeviceLicenseRequest(request):
    try:
        logger.info('updateDeviceLicenseRequest')
        print('updateDeviceLicenseRequest')
        license_manager = management['license-manager']
        reg_data = await request.json()
        userId = reg_data['userId']
        deviceAddress = reg_data['deviceAddress']
        programs = reg_data['programs']
        program_list = list(programs.split("-"))
        users = reg_data['users']
        print(userId)
        print(deviceAddress)
        # for record in cameraip:
        myquery = {"$and": [{"user_id": userId}]}
        newvalues = {
            "$set": {"device_license": deviceAddress, "device_license_status": "requested", "programs": program_list,
                     "users": users}}

        license_manager.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCameraLicenseRequest(request):
    try:
        logger.info('updateCameraLicenseRequest')
        print('updateCameraLicenseRequest')
        license_manager = management['license-manager']
        reg_data = await request.json()
        userId = reg_data['userId']
        cameraId = reg_data['cameraId']
        status = reg_data['status']
        license_file = reg_data['licenseFile']

        asdf = license_manager.update_one(
            {'user_id': userId},
            {'$set': {
                "camera_license_data.$[elem].camera_license_status": status,
                "camera_license_data.$[elem].camera_license_file": license_file}},
            upsert=False,
            array_filters=[
                {
                    "elem.camera_id": cameraId,
                }
            ]
        )
        print(asdf.raw_result)
        # license_manager.find_and_modify(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateDeviceLicense(request):
    try:
        logger.info('updateDeviceLicense')
        print('updateDeviceLicense')
        license_manager = management['license-manager']
        reg_data = await request.json()
        userId = reg_data['userId']
        status = reg_data['status']
        license_file = reg_data['licenseFile']
        print(userId)

        # for record in cameraip:
        myquery = {"$and": [{"user_id": userId}]}
        newvalues = {"$set": {"device_license_status": status, "device_license_file": license_file}}

        license_manager.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateDeviceLicenseData(request):
    try:
        logger.info('updateDeviceLicenseData')
        print('updateDeviceLicenseData')
        license_manager = management['license-manager']
        reg_data = await request.json()
        userId = reg_data['userId']
        data = reg_data['data']
        print(userId)

        # for record in cameraip:
        myquery = {"$and": [{"user_id": userId}]}
        newvalues = {"$set": {"device_license_data": data}}

        license_manager.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updatePortalLicenseRequest(request):
    try:
        logger.info('updateLicenseRequest')
        print('updateLicenseRequest')
        users = management.users
        reg_data = await request.json()
        email = reg_data['email']
        print(email)
        # for record in cameraip:
        myquery = {"email": email}
        newvalues = {"$set": {"licenseRequest": "requested"}}

        users.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateLicense(request):
    try:
        logger.info('updateLicense')
        print('updateLicense')
        camera = management.camera
        reg_data = await request.json()
        cameraname = reg_data['cameraname']
        license = reg_data['license']
        print(cameraname)
        # for record in cameraip:
        myquery = {"cameraname": cameraname}
        newvalues = {"$set": {"license": license, "newlicense": "true"}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updatePortalLicense(request):
    try:
        logger.info('updateLicense')
        print('updateLicense')
        users = management.users
        reg_data = await request.json()
        email = reg_data['email']
        license = reg_data['license']

        myquery = {"email": email}
        newvalues = {"$set": {"license": license}}

        users.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def createRole(request):
    try:
        reg_data = await request.json()
        # logger.info(reg_data)
        roles = management.roles

        rolename = reg_data['rolename']
        options = reg_data['options']
        roleDepartment = reg_data['roleDepartment']

        # password = bcrypt.hashpw(reg_data['password']).decode('utf-8')
        created = datetime.utcnow()

        user_id = roles.insert({
            'role_name': rolename,
            'pages': options,
            'department': roleDepartment,
        })
        result = {'rolename': rolename + ' registered'}

        response_obj = ({'result': result})
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteRole(request):
    try:
        reg_data = await request.json()
        # logger.info(reg_data)
        roles = management.roles

        rolename = reg_data['rolename']
        myquery = {"role_name": rolename}
        x = roles.delete_many(myquery)
        result = {'rolename': rolename + ' deleted'}

        response_obj = ({'result': result})
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteUser(request):
    try:
        reg_data = await request.json()
        # logger.info(reg_data)
        users = management.users

        email = reg_data['email']
        myquery = {"email": email}
        x = users.delete_many(myquery)
        result = {'user': email + ' deleted'}

        response_obj = ({'result': result})
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def allUsers(request):
    try:
        reg_data = await request.json()
        userId = reg_data['userId']
        users = management.users
        response = users.find({'superadmin': userId})
        # logger.info(cursor.size)
        full_data = []

        for document in response:
            details = {}
            # logger.info(document)
            details['email'] = document['email']
            details['last_name'] = document['last_name']
            details['first_name'] = document['first_name']
            details['role'] = document['role']
            full_data.append(details)

        return web.json_response(full_data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def get_camstatus(request):
    print('get_camstatus')
    try:
        reg_data = await request.json()
        date = reg_data['date']
        print(date)
        users = mydb_notification.cameraStatus

        response = users.find({})
        # logger.info(cursor.size)
        # print(response)
        full_data_face = []

        for document_face in response:
            details_face = {}
            data_new = []
            # logger.info(document)
            details_face['Data'] = document_face['Data']
            details_face['cameraname'] = document_face['cameraname']
            details_face['cameraip'] = document_face['cameraip']
            details_face['user_id'] = document_face['user_id']

            for date_val in document_face['Data']:
                data_val = {}
                data_val['message'] = date_val['message']
                data_val['time'] = date_val['time']
                data_val['blurValu'] = date_val['blurValu']
                date_obj = datetime.strptime(date_val['time'], '%Y-%m-%d %H:%M:%S')
                # print(date_obj)
                if date_obj.strftime('%Y-%m-%d') == date:
                    # print(date_val)
                    # print(data_new)
                    # print(data_val)
                    data_new.append(data_val)
                    # print(data_new)
            # print(data_new)
            details_face['Data'] = data_new
            # print(details_face)
            full_data_face.append(details_face)

        # logger.info(cursor.size)
        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def get_superadmin(request):
    try:
        reg_data = await request.json()
        userId = reg_data['userId']
        users = management.users
        response = users.find({'userId': userId})
        # logger.info(cursor.size)
        full_data = []

        for document in response:
            details = {}
            # logger.info(document)
            details['email'] = document['email']
            details['last_name'] = document['last_name']
            details['first_name'] = document['first_name']
            details['role'] = document['role']
            full_data.append(details)

        return web.json_response(full_data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def allRoles(request):
    try:
        roles = management.roles

        cursor_face = roles.find({})
        # logger.info(cursor.size)
        full_data_face = []

        for document_face in cursor_face:
            details_face = {}
            # logger.info(document)
            details_face['role_name'] = document_face['role_name']
            details_face['department'] = document_face['department']
            details_face['pages'] = document_face['pages']
            full_data_face.append(details_face)

        return web.json_response(full_data_face)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def allPages(request):
    try:
        pages = management.pages

        cursor_face = pages.find({})
        # logger.info(cursor.size)
        full_data = []

        for document in cursor_face:
            details = {}
            # logger.info(document)
            details['pages'] = document['pages']
            full_data.append(details)

        return web.json_response(full_data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getUserRoles(request):
    roles = management.roles
    role_data = await request.json()
    rolename = role_data['rolename']

    response = roles.find_one({'role_name': rolename})

    if response:
        out = {}
        out['role_name'] = response['role_name']
        out['pages'] = response['pages']
        response_obj = out
    else:
        response_obj = ({"result": "No results found"})
    return web.json_response(response_obj)


async def groupList(request):
    groups = management.groups
    result = ""
    reg_data = await request.json()
    userId = reg_data['userId']

    response = groups.find({'userId': userId},
                           {'_id': 0, 'cameras': 1, 'groupname': 1, 'canvasName': 1, 'userId': 1, 'superadmin': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        group_array = []
        for doc in response:
            group_array.append(doc)
        result = group_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def groupListAll(request):
    groups = management.groups
    result = ""
    reg_data = await request.json()
    superadmin = reg_data['superadmin']

    response = groups.find({'superadmin': superadmin},
                           {'_id': 0, 'cameras': 1, 'groupname': 1, 'canvasName': 1, 'userId': 1, 'superadmin': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        group_array = []
        for doc in response:
            group_array.append(doc)
        result = group_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def approvalList(request):
    approverList = visitor_management['approver-list']
    result = ""
    response = approverList.find({})

    # json.dumps(obj, default=json_util.default)
    if response:
        full_data = []

        for document in response:
            details = {}
            # logger.info(document)
            details['approver'] = document['approver']
            details['title'] = document['title']
            details['department'] = document['department']
            details['id'] = str(ObjectId(document['_id']))
            details['user'] = document['user']

            full_data.append(details)
        result = full_data
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def updateRequest(request):
    try:
        # print('updateRequest')
        approverList = visitor_management['approver-list']
        visitorList = visitor_management['visitors']
        reg_data = await request.json()
        data = reg_data['data']
        visitorData = reg_data['visitorData']

        myquery = {"_id": ObjectId(data[0]['id'])}

        newValues = {"date": visitorData['date'], "interviewer": visitorData['interviewer'],
                     "title": visitorData['title'],
                     "approver": visitorData['approver']
            , "status": visitorData['status'], "requestor_title": visitorData['requestor_title'],
                     "period": visitorData['period'], "reason": visitorData['reason']
            , "place": visitorData['place'], "request_status": "Requested",
                     "requestor_department": visitorData['requestor_department'],
                     "entryArea": visitorData['entryArea'],
                     "approved_result": "pending"
            , "type": visitorData['type'], "request_area": visitorData['request_area'],
                     "requestor": visitorData['requestor']
            , "visitorName": visitorData['visitorName'], "companyName": visitorData['companyName'],
                     "mobileNo": visitorData['mobileNo'],
                     "region": visitorData['region']}
        setvalues = {"$set": newValues}

        visitorList.insert(visitorData)
        result = {"result": "updated"}
        return web.json_response(result)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def approveRequest(request):
    try:
        # print('updateRequest')
        visitorList = visitor_management['visitors']
        reg_data = await request.json()
        data = reg_data['data']
        # print(data)

        myquery = {"_id": ObjectId(data['id'])}
        newValues = {"approve_status": "Approved"}
        setvalues = {"$set": newValues}
        visitorList.update_one(myquery, setvalues)

        result = {"result": "updated"}
        return web.json_response(result)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateVisitorRegisteredImage(request):
    try:
        visitorList = visitor_management['visitors']
        reg_data = await request.json()
        imagePath = reg_data['imagePath']
        id = reg_data['id']
        myquery = {"_id": ObjectId(id)}
        newvalues = {"$set": {"registeredImage": imagePath}}

        visitorList.update_one(myquery, newvalues)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def visitorsList(request):
    visitorList = visitor_management['visitors']
    result = ""
    response = visitorList.find({})

    # json.dumps(obj, default=json_util.default)
    if response:
        full_data = []

        for document in response:
            details = {}
            # logger.info(document)
            details['visitorName'] = document['visitorName']
            details['companyName'] = document['companyName']
            details['mobileNo'] = document['mobileNo']
            details['id'] = str(ObjectId(document['_id']))
            details['region'] = document['region']
            details['type'] = document['type']
            details['approver'] = document['approver']
            details['requestor_department'] = document['requestor_department']
            details['request_area'] = document['request_area']
            details['requestor'] = document['requestor']
            details['approve_status'] = document['approve_status']
            details['entryArea'] = document['entryArea']
            details['user'] = document['user']
            details['period'] = document['period']
            details['status'] = document['status']
            details['request_status'] = document['request_status']
            details['registeredImage'] = document['registeredImage']

            full_data.append(details)
        result = full_data
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def cameralistAll(request):
    camera = management.camera
    result = ""
    reg_data = await request.json()
    superadmin = reg_data['superadmin']
    response = camera.find({'superadmin': superadmin})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            id_obj = str(ObjectId(doc['_id']))

            if '_id' in doc:
                del doc['_id']

                doc['id'] = id_obj
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def cameralistAll1(request):
    camera = management.camera_parking
    result = ""
    reg_data = await request.json()
    superadmin = reg_data['superadmin']
    response = camera.find({'superadmin': superadmin})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            id_obj = str(ObjectId(doc['_id']))

            if '_id' in doc:
                del doc['_id']

                doc['id'] = id_obj
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def cameralist(request):
    camera = management.camera
    result = ""
    reg_data = await request.json()
    # print("reg_data   ----->>",reg_data)
    userId = reg_data['userId']
    response = camera.find({'userId': userId})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            id_obj = str(ObjectId(doc['_id']))

            if '_id' in doc:
                del doc['_id']

                doc['id'] = id_obj
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def programlist(request):
    programs = management.programs
    result = ""

    response = programs.find({}, {'_id': 0})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def all_program_list(request):
    programs = management.programs
    result = ""

    response = programs.find({}, {'_id': 0})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def allProgramListbySection(request):
    programs = management.programs
    result = ""
    reg_data = await request.json()
    section = reg_data['section']

    response = programs.find({'section': section}, {'_id': 0})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def camerabyCameraIP(request):
    try:
        camera = management.camera
        reg_data = await request.post()

        cameraip = reg_data['cameraip']
        result = ""

        myquery = {"cameraname": cameraip}
        response = camera.find(myquery, {'_id': 0})

        # json.dumps(obj, default=json_util.default)
        if response:
            # result = dumps(response)
            cam_array = []
            for doc in response:
                cam_array.append(doc)
            result = cam_array
            # logger.info(result)
        else:
            result = {"result": "No results found"}
        return web.json_response(result)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateExeStartStopStatus(request):
    try:
        camera = management.camera
        reg_data = await request.json()
        deviceip = reg_data['deviceip']
        cameraname = reg_data['cameraname']
        userId = reg_data['userId']
        containerID = reg_data['containerID']
        hostName = reg_data['hostName']
        dockerIP = reg_data['dockerIP']
        # myquery = { "cameraname": cameraname }
        myquery = {"$and": [{"cameraname": cameraname}, {"deviceip": deviceip}, {"superadmin": userId}]}
        newvalues = {"$set": {"containerID": containerID, "hostName": hostName, "dockerIP": dockerIP}}

        camera.update_one(myquery, newvalues)
        # logger.infoing the data inserted

        # return "updated"
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateProgramSS(request):
    try:
        camera = management.camera
        reg_data = await request.json()
        ss = reg_data['ss']
        deviceip = reg_data['deviceip']
        cameraname = reg_data['cameraname']
        userId = reg_data['userId']
        alertOnTrigger = reg_data['alertOnTrigger']
        runningStatus = reg_data['runningStatus']
        # myquery = { "cameraname": cameraname }
        myquery = {"$and": [{"cameraname": cameraname}, {"superadmin": userId}]}
        if (alertOnTrigger == ""):
            newvalues = {"$set": {"ss": ss, "runningstatus": runningStatus}}
        else:
            newvalues = {"$set": {"ss": ss, "alertOnTrigger": alertOnTrigger, "runningstatus": runningStatus}}

        camera.update_one(myquery, newvalues)
        # logger.infoing the data inserted

        # return "updated"
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateTestStatus(request):
    try:
        camera = management.camera
        reg_data = await request.json()
        cameraname = reg_data['cameraname']
        print(cameraname)
        userId = reg_data['userId']
        print(userId)
        analyseStatus = reg_data['analyseStatus']
        qualityControl = reg_data['qualityControl']
        print(qualityControl)
        print(analyseStatus)
        # myquery = { "cameraname": cameraname }
        myquery = {"$and": [{"cameraname": cameraname}, {"userId": userId}]}
        newvalues = {"$set": {"analyse-status": analyseStatus, "quality-control": qualityControl}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateSelectedProgram(request):
    try:
        camera = management.camera
        reg_data = await request.json()
        program = reg_data['program']
        cameraip = reg_data['cameraip']
        cameraname = reg_data['cameraname']
        tracklist = reg_data['trackList']
        trackStatus = reg_data['trackStatus']
        userId = reg_data['userId']
        alertLiveImage = reg_data['alertLiveImage']
        edgeCamera = reg_data['edgeCamera']
        programHistory = [program]
        # myquery = { "cameraip": cameraip }
        myquery = {"$and": [{"cameraip": cameraip}, {"cameraname": cameraname}, {"superadmin": userId}]}
        newvalues = {"$set": {"selectedprogram": program, "programhistory": programHistory, "frstracklist": tracklist,
                              "trackstatus": trackStatus, "alertSnap": alertLiveImage, "info": edgeCamera}}

        camera.update_one(myquery, newvalues)
        '''mongo.db.camera.update_one(
            {"cameraip": cameraip},
            {
                "$set": {
                    "selectedprogram": program
                }
            }
        )'''

        # logger.infoing the data inserted
        cursor = camera.find()
        for record in cursor:
            logger.info(record)

        # return "updated"
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateIntrusionPlan(request):
    try:
        # logger.info('test')
        intrusionFloorplan = management['intrusion-plan']
        reg_data = await request.post()
        canvasJson = reg_data['jsonData']
        canvasName = reg_data['canvasName']
        cameraip = reg_data['cameraip']
        cameraname = reg_data['cameraname']
        image = reg_data['image']
        # grouplist = '[{"name": "group1", "cameras": ["Camera1", "Camera2"]}, {"name": "group2", "cameras": ["Camera3", "Camera4"]}]'
        # logger.info(canvasJson)

        row = {}
        row['canvasdata'] = canvasJson
        row['canvasName'] = canvasName
        row['cameraip'] = cameraip
        row['cameraname'] = cameraname
        row['image'] = image

        intrusionFloorplan.insert(row)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getSavedIntrusions(request):
    intrusionplan = management['intrusion-plan']
    result = ""

    response = intrusionplan.find({}, {'_id': 0, 'canvasdata': 1, 'canvasName': 1, 'image': 1, 'cameraname': 1,
                                       'cameraip': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def getZonedFloorPlanbyname(request):
    try:
        print('getZonedFloorPlanbyname')
        zonedFloorplan = management['zoned-floorplan']
        reg_data = await request.post()
        # logger.info(reg_data)
        canvasName = reg_data['canvasName']
        print(canvasName)
        userId = reg_data['userId']
        print(userId)
        # logger.info('zonedfloorplan ' + canvasName)
        query = {'$and': [{'canvasName': canvasName}, {'userId': userId}]}
        response = zonedFloorplan.find_one(query)
        # logger.info(response)
        if response:
            out = {}
            out['canvasName'] = response['canvasName']
            out['canvasdata'] = response['canvasdata']

            response_obj = out
        else:
            response_obj = ({"result": "No results found"})

        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getZonedFloorPlan(request):
    zonedFloorplan = management['zoned-floorplan']
    result = ""

    reg_data = await request.json()
    userId = reg_data['userId']

    response = zonedFloorplan.find({'userId': userId},
                                   {'_id': 0, 'canvasdata': 1, 'canvasName': 1, 'userId': 1, 'superadmin': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def getZonedFloorPlanAll(request):
    zonedFloorplan = management['zoned-floorplan']
    result = ""

    reg_data = await request.json()
    superadmin = reg_data['superadmin']

    response = zonedFloorplan.find({'superadmin': superadmin},
                                   {'_id': 0, 'canvasdata': 1, 'canvasName': 1, 'userId': 1, 'superadmin': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def getZonedFloorPlanAll(request):
    zonedFloorplan = management['zoned-floorplan']
    result = ""

    reg_data = await request.json()
    superadmin = reg_data['superadmin']

    response = zonedFloorplan.find({'superadmin': superadmin}, {'_id': 0, 'canvasdata': 1, 'canvasName': 1})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def updateZonedFloorPlan(request):
    try:
        logger.info('updateZonedFloorPlan')
        print('updateZonedFloorPlan')
        zonedFloorplan = management['zoned-floorplan']
        reg_data = await request.post()
        canvasJson = reg_data['jsonData']
        canvasName = reg_data['canvasName']
        userId = reg_data['userId']
        superadmin = reg_data['superadmin']
        print(superadmin)
        print('------')
        # grouplist = '[{"name": "group1", "cameras": ["Camera1", "Camera2"]}, {"name": "group2", "cameras": ["Camera3", "Camera4"]}]'
        # logger.info(canvasJson)

        row = {}
        row['canvasdata'] = canvasJson
        row['canvasName'] = canvasName
        row['userId'] = userId
        row['superadmin'] = superadmin

        zonedFloorplan.insert(row)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def saveMapData(request):
    try:
        logger.info('saveMapData')
        mapPlan = management['map-plan']
        reg_data = await request.post()
        canvasJson = reg_data['jsonData']
        canvasName = reg_data['canvasName']

        row = {}
        row['canvasdata'] = canvasJson
        row['canvasName'] = canvasName

        mapPlan.insert(row)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getMapPlan(request):
    mapPlan = management['map-plan']
    result = ""

    response = mapPlan.find({}, {'_id': 0, 'canvasdata': 1, 'canvasName': 1})

    if response:

        cam_array = []
        for doc in response:
            cam_array.append(doc)
        result = cam_array

    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def addGroupList(request):
    try:
        logger.info('addGroupList')
        groups = management.groups
        reg_data = await request.post()
        grouplist = reg_data['grouplist']
        jsonData = reg_data['jsonData']
        canvasName = reg_data['canvasName']
        userId = reg_data['userId']
        superadmin = reg_data['superadmin']

        grouparray = json.loads(grouplist)

        for each in grouparray:
            row = {}
            logger.info(each['name'])
            row['groupname'] = each['name']
            row['cameras'] = each['cameras']
            row['jsonData'] = jsonData
            row['canvasName'] = canvasName
            row['userId'] = userId
            row['superadmin'] = superadmin

            groups.insert(row)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCoOrdinatesTest(request):
    try:
        logger.info('updateCoOrdinatesTest')
        camera = management.camera
        reg_data = await request.post()
        cameraip = reg_data['cameraip']
        cameraname = reg_data['cameraname']
        jsonData = reg_data['jsonData']
        intrusionImageUrl = reg_data['intrusionImageUrl']
        intrusionSnap = reg_data['intrusionSnap']
        canvasSize = reg_data['canvasSize']
        coOrdinates = reg_data['coOrdinates']
        status = reg_data['status']
        myquery = {"cameraname": cameraname}
        if status == 'new':
            # print(status)
            newvalues = {"$set": {"co_ordinates": [], "intrusioncanvas": jsonData, "intrusionCanvasSize": canvasSize,
                                  "intrusionSnap": intrusionSnap, "intrusionImageUrl": intrusionImageUrl}}
            camera.update_one(myquery, newvalues)
        newvalues = {"$push": {"co_ordinates": coOrdinates}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCameraStatus(request):
    try:
        logger.info('updateCameraStatus')
        camera = management.camera
        reg_data = await request.json()
        superadmin = reg_data['superadmin']
        status = reg_data['status']
        # myquery = {"cameraname": cameraname, "userId": userId}
        myquery = {"$and": [{"superadmin": superadmin}]}
        newvalues = {"$set": {"status": status}}
        camera.update(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCameraUrl(request):
    try:
        logger.info('updateCameraUrl')
        camera = management.camera
        reg_data = await request.json()
        cameraname = reg_data['cameraname']
        userId = reg_data['userId']
        type = reg_data['type']
        folderPath = reg_data['folderPath']
        # myquery = {"cameraname": cameraname, "userId": userId}
        myquery = {"$and": [{"cameraname": cameraname}, {"userId": userId}]}
        if (type == ''):
            newvalues = {"$set": {"url": folderPath}}
            camera.update_one(myquery, newvalues)
        else:
            newvalues = {"$set": {"url": folderPath, "info": type}}
            camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateProgramConfig(request):
    try:
        logger.info('updateProgramConfig')
        print('updateProgramConfig')
        camera = management.camera
        reg_data = await request.json()
        cameraname = reg_data['cameraname']
        userId = reg_data['userId']
        angle = reg_data['angle']
        connectorPort = reg_data['connectorPort']
        managementIp = reg_data['managementIp']
        print(cameraname)
        # for record in cameraip:
        connectorUrl = 'http://' + managementIp + ':' + connectorPort
        myquery = {"cameraname": cameraname, "userId": userId}
        newvalues = {"$set": {"detectionurl": connectorUrl, "rotateangle": angle}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateFiatCoOrdinatesTest(request):
    try:
        logger.info('updateFiatCoOrdinatesTest')
        print('updateFiatCoOrdinatesTest')
        camera = management.camera
        reg_data = await request.post()
        cameraname = reg_data['cameraname']
        print(cameraname)
        coOrdinates = reg_data['coOrdinates']
        status = reg_data['status']
        templeteurl = reg_data['templeteurl']
        # logger.info(coOrdinates)
        print(coOrdinates)
        # for record in cameraip:
        myquery = {"cameraname": cameraname}
        if status == 'new':
            # print(status)
            newvalues = {"$set": {"co_ordinates": [], "templeteUrl": templeteurl}}
            camera.update_one(myquery, newvalues)
        newvalues = {"$push": {"co_ordinates": coOrdinates}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateAlignmentCoOrdinatesTest(request):
    try:
        logger.info('updateAlignmentCoOrdinatesTest')
        print('updateAlignmentCoOrdinatesTest')
        print('enter')
        camera = management.camera
        reg_data = await request.post()
        projectName = reg_data['projectName']
        print(projectName)
        userId = reg_data['userId']
        print(userId)
        coOrdinates = reg_data['coOrdinates']
        print(coOrdinates)
        status = reg_data['status']
        print(status)
        templeteurl = reg_data['templeteurl']
        print(templeteurl)
        measurements = reg_data['measurements']
        templeteImage = reg_data['templeteImage']
        print(measurements)
        saveLevel = reg_data['saveLevel']
        print(saveLevel)
        program = reg_data['program']
        # logger.info(coOrdinates)
        # for record in cameraip:

        myquery = {"cameraname": projectName, "userId": userId}
        if (saveLevel == '0'):
            if status == 'new':
                print(status)
                print(templeteurl)
                newvalues = {
                    "$set": {"coordinates": [], "templete": templeteurl,
                             "status": "true", "measurements": [],
                             "templeteImage": templeteImage, "maxHash": "",
                             "maxScore": ""}}
                camera.update_one(myquery, newvalues)

            newvalues = {"$push": {"coordinates": coOrdinates,
                                   "measurements": measurements}}

        elif (saveLevel == '1'):
            if status == 'new':
                print(status)
                print(templeteurl)
                if (program == 'assemblynotch'):
                    if (projectName == 'cameraB'):
                        newvalues = {"$set": {"coordinates-L2": [],
                                              "status": "true",
                                              "measurements": [],
                                              "templete-L2": templeteurl,
                                              "maxHash": "", "maxScore": ""}}
                    else:
                        newvalues = {"$set": {"coordinates-hole": [],
                                              "status": "true",
                                              "measurements": [],
                                              "templeteImage": templeteImage,
                                              "maxHash": "",
                                              "maxScore": ""}}

                else:

                    newvalues = {"$set": {"coordinates-L2": [],
                                          "templete": templeteurl,
                                          "coordinates-sealant": [],
                                          "status": "true", "measurements": [],
                                          "templeteImage": templeteImage,
                                          "maxHash": "", "maxScore": ""}}

                camera.update_one(myquery, newvalues)

            if (program == 'assemblynotch'):
                if (projectName == 'cameraA'):
                    newvalues = {"$push": {"coordinates-hole": coOrdinates,
                                           "measurements": measurements}}
                elif (projectName == 'cameraB'):
                    newvalues = {"$push": {"coordinates-L2": coOrdinates,
                                           "measurements": measurements}}
            else:
                newvalues = {"$push": {"coordinates-L2": coOrdinates,
                                       "measurements": measurements}}



        else:
            if status == 'new':
                print(status)
                print(templeteurl)
                newvalues = {
                    "$set": {"screw_holes": [], "templete": templeteurl,
                             "status": "true", "measurements": [],
                             "templeteImage": templeteImage, "maxHash": "",
                             "maxScore": ""}}
                camera.update_one(myquery, newvalues)
            newvalues = {"$push": {"screw_holes": coOrdinates,
                                   "measurements": measurements}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateAlignmentCoOrdinatesTest1(request):
    try:
        logger.info('updateAlignmentCoOrdinatesTest')
        print('updateAlignmentCoOrdinatesTest')
        print('enter')
        print()
        camera = management.camera_parking
        print("requsting api")
        reg_data = await request.post()
        cor = reg_data['coOrdinates']
        print(reg_data['coOrdinates'])
        for doc in cor:
            print("hai", doc, "and")
            print("hai", type(doc))

        print("api resp", reg_data)
        projectName = reg_data['projectName']
        print(projectName)
        userId = reg_data['userId']
        print(userId)
        coOrdinates = reg_data['coOrdinates']
        print(coOrdinates)
        status = reg_data['status']
        print(status)
        templeteurl = reg_data['templeteurl']
        print(templeteurl)
        measurements = reg_data['measurements']
        templeteImage = reg_data['templeteImage']
        print(measurements)
        saveLevel = reg_data['saveLevel']
        print(saveLevel)
        program = reg_data['program']
        # logger.info(coOrdinates)
        # for record in cameraip:

        myquery = {"cameraname": projectName, "userId": userId}
        if (saveLevel == '0'):
            if status == 'new':
                print(status)
                print(templeteurl)
                newvalues = {
                    "$set": {"coordinates": [], "templete": templeteurl,
                             "status": "true", "measurements": [],
                             "templeteImage": templeteImage, "maxHash": "",
                             "maxScore": ""}}
                camera.update_one(myquery, newvalues)

            # newvalues = {"$update_": {"coordinates": coOrdinates,
            #                        "measurements": measurements}}
            newvalues = {
                "$set": {"coordinates": coOrdinates, "templete": templeteurl,
                         "status": "true", "measurements": measurements,
                         "templeteImage": templeteImage, "maxHash": "",
                         "maxScore": ""}}
            camera.update_one(myquery, newvalues)
        elif (saveLevel == '1'):
            if status == 'new':
                print(status)
                print(templeteurl)
                if (program == 'assemblynotch'):
                    if (projectName == 'cameraB'):
                        newvalues = {"$set": {"coordinates-L2": [],
                                              "status": "true",
                                              "measurements": [],
                                              "templete-L2": templeteurl,
                                              "maxHash": "", "maxScore": ""}}
                    else:
                        newvalues = {"$set": {"coordinates-hole": [],
                                              "status": "true",
                                              "measurements": [],
                                              "templeteImage": templeteImage,
                                              "maxHash": "",
                                              "maxScore": ""}}

                else:

                    newvalues = {"$set": {"coordinates-L2": [],
                                          "templete": templeteurl,
                                          "coordinates-sealant": [],
                                          "status": "true", "measurements": [],
                                          "templeteImage": templeteImage,
                                          "maxHash": "", "maxScore": ""}}

                camera.update_one(myquery, newvalues)

            if (program == 'assemblynotch'):
                if (projectName == 'cameraA'):
                    newvalues = {"$push": {"coordinates-hole": coOrdinates,
                                           "measurements": measurements}}
                elif (projectName == 'cameraB'):
                    newvalues = {"$push": {"coordinates-L2": coOrdinates,
                                           "measurements": measurements}}
            else:
                newvalues = {"$push": {"coordinates-L2": coOrdinates,
                                       "measurements": measurements}}



        else:
            if status == 'new':
                print(status)
                print(templeteurl)
                newvalues = {
                    "$set": {"screw_holes": [], "templete": templeteurl,
                             "status": "true", "measurements": [],
                             "templeteImage": templeteImage, "maxHash": "",
                             "maxScore": ""}}
                camera.update_one(myquery, newvalues)
            newvalues = {"$push": {"screw_holes": coOrdinates,
                                   "measurements": measurements}}

        camera.update_one(myquery, newvalues)
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCoOrdinates(request):
    try:
        camera = management.camera
        reg_data = await request.post()
        cameraip = reg_data['cameraip']
        coOrdinates = reg_data['coOrdinates']
        for record in cameraip:
            myquery = {"cameraip": record}
            newvalues = {"$push": {"co_ordinates": coOrdinates}}

            camera.update_one(myquery, newvalues, upsert=True)

        # return "updated"
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updatePortalNotification(request):
    try:
        notificationDB = management['alert-notification']
        content = await request.json()
        group = content['group']
        users = content['users']
        notification = content['notification']

        row = {}
        row['users'] = users
        row['datetime'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        row['plans'] = group
        row['notification'] = notification

        notificationDB.insert(row)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateProgramList(request):
    try:
        camera = management.camera
        content = await request.json()

        programNames = tuple(content['programNames'])

        camera.update({}, {"$set": {"programs": programNames}}, multi=True)

        # logger.infoing the data inserted
        cursor = camera.find()
        for record in cursor:
            logger.info(record)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteProgramList(request):
    try:
        content = await request.json()
        camera = management.camera
        cursor = camera.find()
        for record in cursor:

            programs = record['programs']
            if (content['program'] in programs):
                programs.remove(content['program'])
            selectedprogram = record['selectedprogram']
            if (selectedprogram == content['program'].split('.')[0]):
                selectedprogram = ''

            programhistory = record['programhistory']
            if (content['program'].split('.')[0] in programhistory):
                programhistory.remove(content['program'].split('.')[0])
            camera.update({}, {
                "$set": {"programs": programs, "selectedprogram": selectedprogram, "programhistory": programhistory}},
                          multi=True)

        filePath = content['filepath'] + '/' + content['program']
        if os.path.exists(filePath):
            os.remove(filePath)
        else:
            logger.info('File does not exists')

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteCriminalFace(request):
    try:
        content = await request.json()
        key = '_id'
        value = ObjectId(content['id'])
        userId = content['userId']
        documentName = userId + "_encode"

        criminalList = criminalDB_general[documentName]

        unique_client = criminalList.find({'_id': value})
        if unique_client:
            x = criminalList.delete_many({'_id': value})
            print(x)
            '''fileList = glob.glob(content['path'])
            for filePath in fileList:
                try:
                    os.remove(filePath)
                except:
                    logger.info("Error while deleting file : ", filePath)'''

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteAlerts(request):
    try:
        content = await request.json()
        program = content['program']
        userId = content['userId']
        documentName = userId + "_" + program
        name_face = get_name(documentName, mongo_db)
        alertdata_db = mongo_db['alert']
        faceAlert = alertdata_db[name_face]
        x = faceAlert.delete_many({})
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteCameraList(request):
    try:
        cameraList = management['camera']
        x = cameraList.delete_many({})
        sysReg = mydb_notification['sys-reg']
        y = sysReg.delete_many({})
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteCriminalList(request):
    try:
        content = await request.json()
        userId = content['userId']
        out = criminaldata_db.collection_names()
        documentName = userId + "_encode"

        criminaldata_list = criminalDB_general[documentName]
        criminalList = criminaldata_list
        content = await request.json()
        folderPath = content['folderPath']
        # print(folderPath)

        x = criminalList.delete_many({})
        # logger.info(x.deleted_count, " criminal list deleted.")
        fileList = glob.glob(folderPath + '/public/faceimages/faces/' + '/*')
        for filePath in fileList:
            try:
                os.remove(filePath)
                # print(filePath)
            except:
                logger.info("Error while deleting file : ", filePath)
                # print("Error while deleting file : ", filePath)

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def deleteCamera(request):
    try:
        content = await request.json()

        camera = management.camera
        userId = content['userId']
        # myquery = {"cameraip": content['cameraip']}
        myquery = {"$and": [{"cameraip": content['cameraip']}, {"userId": userId}]}
        x = camera.delete_many(myquery)

        deviceip = content['deviceip']
        sysReg = mydb_notification['sys-reg']
        myquery = {"ip": deviceip}
        y = sysReg.delete_many(myquery)
        # logger.info(y.deleted_count, " documents deleted.")

        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateCameras(request):
    try:
        print("updateCameras")
        camera = management.camera
        license_manager = management['license-manager']
        content = await request.json()
        print(content["file"])
        csvfile = open(content["file"])
        userId = content['userId']
        superadmin = content['superadmin']
        detectionurl = content['detectionurl']
        reader = csv.DictReader(csvfile)
        programs = ['face', 'numberplate', 'intrusion', 'gun', 'thermal', 'objectdetection', 'attire']
        isUpdated = "updated"
        header = ["cameraip", "deviceip", "devicename", "location", "url", "name", "cameraname", "type"]

        regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

        for each in reader:
            row = {}
            # logger.info(each['cameraip'])
            print(each["cameraip"])
            if (re.search(regex, each["cameraip"])):
                print("Valid Ip address")
            else:
                print("Invalid Ip address")

            # cameraipdata = camera.find_one({'cameraname': each['cameraname']}, {'userId': userId})
            cameraipdata = camera.find_one({"$and": [{"cameraname": each['cameraname']}, {"userId": userId}]})
            if cameraipdata:
                # logger.info("Already cameraip exists")
                isUpdated = "exists"
            else:
                for field in header:
                    row[field] = each[field]
                row['programs'] = programs
                row['datetime'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                row['status'] = 'false'
                row['selectedprogram'] = ''
                row['programstatus'] = 'false'
                row['runningstatus'] = 'OFF'
                row['programhistory'] = []
                row['ss'] = '0'
                row['info'] = 'url'
                row['factor'] = '25'
                row['factor_inside'] = '5'
                row['enable_face_details'] = '100'
                row['qualitycontrol'] = '5.5'
                row['scenechange'] = '0'
                row['associate'] = 'Associate'
                row['coordinates'] = []
                row['frstracklist'] = []
                row['trackstatus'] = ''
                row['intrusioncanvas'] = ''
                row['intrusionCanvasSize'] = ''
                row['intrusionSnap'] = ''
                row['intrusionImageUrl'] = ''
                row['sanServerIp'] = '192.168.1.96'
                row['vms'] = 'disable'
                row['message'] = ''
                row['newlicense'] = ''
                row['licenseRequest'] = ''
                row['license'] = ''
                row['templete'] = ''
                row['userId'] = userId
                row['superadmin'] = superadmin
                row['alertSnap'] = ''
                row['measurements'] = []
                row['templeteImage'] = ''
                row['analyse-status'] = 'false'
                row['analysed-alert'] = ''
                row['quality-control'] = ''
                row['alertOnTrigger'] = 'false'
                row['maxHash'] = ''
                row['maxScore'] = ''
                row['containerID'] = ''
                row['hostName'] = ''
                row['dockerIP'] = ''
                row['cameraIndex'] = ''
                row['detectionurl'] = detectionurl
                row['detectionConfidence'] = '0.28'
                row['rotateangle'] = '0'

                try:
                    # criminaldata_db = criminaldata_db
                    # criminaldata_list = criminaldata_db["list"]

                    out = criminaldata_db.collection_names()

                    row['dblist'] = out
                except:
                    row['dblist'] = []

                _id = camera.insert(row)
                print(_id)
                '''license_row = {}

                license_row['camera_id'] = str(ObjectId(_id))
                license_row['user_id'] = userId
                license_row['portal_licence'] = ''
                license_row['device_license'] = ''
                license_row['portal_licence_file'] = ''
                license_row['device_license_file'] = ''
                license_row['portal_licence_status'] = ''
                license_row['device_license_status'] = ''

                _id = license_manager.insert(license_row)'''

                myquery = {"$and": [{"user_id": userId}]}
                newvalues = {"$push": {
                    "camera_license_data": {"camera_id": str(ObjectId(_id)), "camera_licence_file": "",
                                            "camera_license_status": ""}}}

                license_manager.update_one(myquery, newvalues)
                isUpdated = "updated"
        # return isUpdated
        response_obj = {'status': isUpdated}
        return web.json_response(response_obj)

    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def createTraining(request):
    try:
        reg_data = await request.json()
        # logger.info(reg_data)
        training = management.training

        flowpoints = reg_data['flowpoints']
        print(flowpoints)
        flowpoints_obj = json.loads(flowpoints)
        print(flowpoints_obj)
        # password = bcrypt.hashpw(reg_data['password']).decode('utf-8')
        created = datetime.utcnow()

        training_id = training.insert({
            'flowpoints': flowpoints,
            'message': '',
            'loss': [],
            'modelpath': [],
            'Selected_Model': '',
            'Training_Name': flowpoints_obj['name'],
            'created': str(created)
        })
        result = {'status': 'registered'}

        response_obj = ({'result': result})
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getSavedTraining(request):
    try:

        sys_db_face = management['training']
        # logger.info(name_face)
        cursor_face = sys_db_face.find({})
        # logger.info(cursor.size)
        data = []

        for document_training in cursor_face:
            id_obj = str(ObjectId(document_training['_id']))

            if '_id' in document_training:
                del document_training['_id']

            document_training['id'] = id_obj
            data.append(document_training)

        return web.json_response(data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateTrainingModel(request):
    try:

        training_db = management['training']
        # logger.info(name_face)
        reg_data = await request.json()

        id = reg_data['id']
        modelVersion = reg_data['modelVersion']

        query = {'_id': ObjectId(id)}
        training_db.update(query, {"$set": {"Selected_Model": modelVersion}})

        programs = management['programs']
        selectedModel = reg_data['selectedModel']
        print(selectedModel)

        program_id = programs.insert({
            'name': selectedModel,
            'description': '',
            'text': selectedModel,
            'type': 'multi',
            'status': 'enable',
            'icon': 'program',
        })

        return web.json_response({'result': 'updated'})
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getStatus(request):
    try:

        sys_db_face = management['status']
        # logger.info(name_face)
        cursor = sys_db_face.find({})
        # logger.info(cursor.size)
        data = []

        for document_status in cursor:
            id_obj = str(ObjectId(document_status['_id']))

            if '_id' in document_status:
                del document_status['_id']

                document_status['id'] = id_obj
            data.append(document_status)

        return web.json_response(data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getAlignmentProjects(request):
    try:
        sys_db_face = management['alignment-projects']
        cursor = sys_db_face.find({})
        data = []
        for document_status in cursor:
            id_obj = str(ObjectId(document_status['_id']))

            if '_id' in document_status:
                del document_status['_id']
                document_status['id'] = id_obj
            data.append(document_status)
        return web.json_response(data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getStatusByName(request):
    try:
        print('getStatusByName')
        status = management['status']
        reg_data1 = await request.json()
        name = reg_data1['name']
        response = status.find({'name': name})
        # logger.info(response)
        data = []
        for document_status in response:
            id_obj = str(ObjectId(document_status['_id']))

            if '_id' in document_status:
                del document_status['_id']

                document_status['id'] = id_obj
            data.append(document_status)

        return web.json_response(data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def updateStatusSS(request):
    try:
        status = management['status'];
        reg_data = await request.json()
        name = reg_data['name']
        userId = reg_data['userId']
        ss = reg_data['ss']
        # myquery = { "name": name }
        myquery = {"$and": [{"name": name}, {"userId": userId}]}
        newvalues = {"$set": {"status": ss}}

        status.update_one(myquery, newvalues)
        # logger.infoing the data inserted

        # return "updated"
        response_obj = {'status': 'updated'}
        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def getLicenseInformation(request):
    try:
        license_manager = management['license-manager']
        reg_data = await request.json()
        userId = reg_data['userId']
        # myquery = { "name": name }
        myquery = {"$and": [{"user_id": userId}]}
        response = license_manager.find(myquery)
        data = []
        for document_status in response:
            id_obj = str(ObjectId(document_status['_id']))

            if '_id' in document_status:
                del document_status['_id']

                document_status['id'] = id_obj
            data.append(document_status)

        # return "updated"
        return web.json_response(data)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        return web.json_response(response_obj)


async def program_status_management(request):
    input_data = await request.json()
    ip = input_data['ip']
    program_management = management['management_program']
    response = program_management.find_one({'ip': ip}, {"_id": 0})
    return web.json_response(response)


def variance_of_laplacian(image):
    # compute the Laplacian of the image and then return the focus
    # measure, which is simply the variance of the Laplacian
    return cv2.Laplacian(image, cv2.CV_64F).var()


async def get_encode_list(request):
    # print("ent")
    data = await request.json()
    # print(data)
    list_name = data['listname']
    # print(list_name)
    hoglist = criminaldata_db[list_name]
    logger.info("get_encode_data" + list_name)
    out_data = {}

    print('len', hoglist.count())
    for x in hoglist.find():
        # logger.info(x)
        build_data_encode = {}
        build_data_encode['encoding'] = x['encoding']
        id = str(ObjectId(x['_id']))
        out_data[id] = build_data_encode
    build_encode_json = {}
    build_encode_json["encode"] = out_data
    logger.info("management get encode ")

    # print(build_encode_json)

    return web.Response(text=json.dumps(build_encode_json), status=200)


async def get_encode_list_mangnum(request):
    # data = await request.json()

    criminaldata_magnum = mongo_db['encode_magnum']

    criminaldata_list_magnum = criminaldata_magnum['database']

    out_data = {}

    print('encode len', criminaldata_list_magnum.count())
    for x in criminaldata_list_magnum.find():
        # logger.info(x)
        build_data_encode = {}
        build_data_encode['encoding'] = x['encoding']
        id = str(ObjectId(x['_id']))
        out_data[id] = build_data_encode
    build_encode_json = {}
    build_encode_json["encode"] = out_data
    logger.info("management get encode ")

    # print(build_encode_json)

    return web.Response(text=json.dumps(build_encode_json), status=200)


async def get_template_snap(request):
    out_data = await request.json()
    # save_path = out_data['location']

    save_path = os.path.join(management_path, "public", "fiatimages", "snapimages")
    device_ip = out_data['device_ip']
    programName = out_data['programName']
    url = out_data['url']

    indata = {'programName': programName, "url": url}
    print(indata)
    try:
        '''url = 'http://' + device_ip + ':' + str(Node_run_port) + '/template_snap'
        print(url)
        r = requests.post(url,data=json.dumps(indata))
        res = r.json()
        save_name = os.path.join(save_path, res['name'])
        if os.path.isdir(save_path):
            pass
        else:
            os.makedirs(save_path)
        jpg_as_text = res['datapoint']
        nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
        img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        cv2.imwrite(save_name, img_final)
        result_temp = 'success'
        temp_path = res['name']
        status_num = 200'''
        cap = cv2.VideoCapture(url)
        _, gtemyframe = cap.read()
        print(gtemyframe)
        if np.shape(gtemyframe) == ():
            result_temp = 'error'
            temp_path = ''
            status_num = 500
        else:
            ctime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_name_img1 = "snap_" + ctime + ".jpg"
            file_name_img2 = file_name_img1.replace(" ", "_")
            file_name_img = file_name_img2.replace(":", "-")
            save_name = os.path.join(save_path, file_name_img)
            if os.path.isdir(save_path):
                pass
            else:
                os.makedirs(save_path)
            cv2.imwrite(save_name, gtemyframe)
            result_temp = 'success'
            temp_path = file_name_img
            status_num = 200
            cap.release()
    except Exception as e:
        print(e)
        result_temp = 'error'
        temp_path = ''
        status_num = 500
    output_res = {}
    output_res['result'] = result_temp
    output_res['path'] = temp_path
    return web.Response(text=json.dumps(output_res), status=status_num)


async def crop_template(request):
    out_data = await request.post()
    try:
        print("crop temp", out_data)
        img_path = out_data['path']
        savePath1 = out_data['savePath']
        imgNameArr = img_path.split('/')
        # savePath = savePath+imgNameArr[len(imgNameArr)-1]
        N_Name = 'img_' + datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f") + ".jpg"
        savePath = os.path.join(savePath1, N_Name)
        coordinate = out_data['coordinate']
        print("coorditans", coordinate)
        img = cv2.imread(img_path)
        print("image_path", img)
        bbox = list(map(int, coordinate.split(",")))
        B = np.reshape(bbox, (-1, 2))
        start_point = ((min(B[:, 0])), (min(B[:, 1])))
        end_point = ((max(B[:, 0])), (max(B[:, 1])))
        crop_img = img[start_point[1]:end_point[1], start_point[0]:end_point[0]]
        print("crop_image", crop_img)
        cv2.imwrite(savePath, crop_img)

        crop_temp = "success"
        status_num = 200
    except:
        savePath = ""
        crop_temp = "error"
        status_num = 500
    output_res = {}
    output_res['result'] = crop_temp
    output_res['path'] = savePath
    return web.Response(text=json.dumps(output_res), status=200)


async def get_system_address(request):
    address_out = get_address(sysPass, disk)
    return web.json_response({'address': address_out})


async def upload_register(request):
    out_data = await request.json()
    for key, value in out_data.items():
        print(key, value['name'])

        criminaldata_list = criminaldata_db[key]
        try:
            out = criminaldata_list.insert_one(value)

        except:
            print("mogo error")

    return web.json_response({'result': 'success'})


async def get_alert_details(request):
    found_list = await request.json()
    id_mongo = found_list['id']

    qu = {'_id': ObjectId(id_mongo)}
    list_doc = criminaldata_db[found_list['model']]
    unique_client = list_doc.find_one(qu, {"_id": 0, "encoding": 0, "loc": 0})
    if unique_client:
        print(unique_client)
        result_data = unique_client
    else:
        result_data = {}
    return web.json_response(result_data)


async def get_snaps(request):
    snap = await request.json()
    try:
        jpg_as_text = snap['jpg_as_text']
        name = snap['name']
        folder_name = snap['alert_name']
        nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
        img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        full_path = os.path.join(management_path, 'public', 'alert', folder_name)
        if os.path.isdir(full_path):
            pass
        else:
            os.makedirs(full_path)

        name_path = os.path.join(full_path, name)
        # print(name_path)
        cv2.imwrite(name_path, img_final)
        result = "success"

    except Exception as e:
        print(e)
        result = "error"

    return {"result": result}


async def serverCheck(request):
    logger.info("5000 port running")
    response_obj = {'status': 'success'}
    return web.json_response(response_obj)


async def port_check(request):
    logger.info("5000 port running")
    response_obj = {'status': 'success'}
    return web.json_response(response_obj)


async def upload_encode_db_full(request):
    out = await request.json()
    userId = out['userId']
    name_list = out['name']
    # name_list = ["1_1224278210_6_951"]

    encode_db = userId + "_encodedum"
    list_deb_user = criminalDB_general[encode_db]
    count = 0
    # list_deb_user.update({}, { "$unset": {"reference": ""}})
    list_deb_user.update({}, {"$pull": {"test": {"$in": ["test"]}}});

    return web.json_response({'result': count})


def upload_data(userId, encodeData):
    list_name = userId + "_encode"
    encode_dbdum = userId + "_encodedum"
    list_deb_dum = criminalDB_general[encode_dbdum]
    list_deb_user = criminalDB_general[list_name]
    print(encodeData)
    _id = list_deb_user.insert_one(encodeData)
    new_user = list_deb_user.find_one({'_id': encodeData["_id"]})
    print(new_user)
    if (new_user != None):
        result = list_deb_dum.delete_one({'_id': encodeData["_id"]})


async def check_gitter(request):
    out = await request.json()
    userId = out['userId']
    encode_db = userId + "_encode"
    encode_dbdum = userId + "_encodedum"
    list_deb_user = criminalDB_general[encode_db]

    normal_list = []
    for x in list_deb_user.find():
        if x["reference"] == "normal":
            normal_list.append(normal_list)

    print(len(normal_list))
    return web.json_response({'result': normal_list})


async def allProgrambySectionProgram(request):
    programs = management['program-config']
    result = ""
    reg_data = await request.json()
    section = reg_data['section']
    program = reg_data['program']
    print(section)
    print(program)
    response = programs.find({"$and": [{'section': section}, {'program': program}]})

    # json.dumps(obj, default=json_util.default)
    if response:
        # result = dumps(response)
        cam_array = []
        for doc in response:
            id_obj = str(ObjectId(doc['_id']))
            if '_id' in doc:
                del doc['_id']
                doc['id'] = id_obj

            cam_array.append(doc)
        result = cam_array
        # logger.info(result)
    else:
        result = {"result": "No results found"}
    return web.json_response(result)


async def program_config_demo(request):
    reg_data = await request.json()
    programs = management['program-config']
    print(reg_data)
    response = programs.find_one(reg_data, {"_id": 0})
    print(response)
    return web.json_response(response)


async def updation_doneGroup(request):
    data = await request.json()
    print(data)
    print("updation_done", data['name'])

    if 'cameraGroup' in data:
        cameraGroup = data['cameraGroup']
    else:
        cameraGroup = False

    if cameraGroup:
        print("GROUP")
        Q_data = [
            {'deviceip': data['device_ip']},
            {'userId': data['userId']}
        ]
    else:
        Q_data = [
            {'deviceip': data['device_ip']},
            {'cameraip': data['cameraip']},
            {'cameraname': data['cameraname']},
            {'userId': data['userId']},
            {'selectedprogram': data['selectedprogram']}
        ]
    print("____________________-")
    print(Q_data)

    try:
        cam_list = management['camera']
        if data['name'] == "encodeupdate":
            st_encode = data['update_status']
            update = {'status': st_encode}
            print(update, Q_data)
            out_con = cam_list.update_many({'$and': Q_data}, {"$set": update}, upsert=False)
            print(out_con.modified_count, out_con.raw_result)

            response_obj = {'status': 'updated'}

        elif data['name'] == 'analyse-status':
            analysestatus = data['update_status']
            update = {'analyse-status': analysestatus}

            out_con = cam_list.update_many({'$and': Q_data}, {"$set": update}, upsert=False)
            print(out_con.modified_count, out_con.raw_result)
            '''out_con = cam_list.update_one({
                '$and': [
                    {'deviceip': data['device_ip']},
                    {'cameraip': data['cameraip']},
                    {'cameraname': data['cameraname']},
                    {'userId': data['userId']}
                ]
            }, {"$set": update}, upsert=False)'''

            # print(out_con.raw_result)

            response_obj = {'status': 'updated'}
        elif data['name'] == 'ss':

            update_ss = {'ss': '0'}
            out_con = cam_list.update_many({'$and': Q_data}, {"$set": update_ss}, upsert=False)
            print(out_con.modified_count, out_con.raw_result)

            response_obj = {'status': 'updated'}
        elif data['name'] == "message":
            logger.info('update message')
            st_encode = data['programrunstatus']
            update = {'message': st_encode}
            out_con = cam_list.update_many({'$and': Q_data}, {"$set": update}, upsert=False)
            print(out_con.modified_count, out_con.raw_result)
            response_obj = {'status': 'updated'}

        elif data['name'] == 'runningstatus':
            logger.info('runningstatus')
            st = data['programrunstatus']
            update = {'runningstatus': st}

            print("programrunstatus", update)

            out_con = cam_list.update_many({'$and': Q_data}, {"$set": update}, upsert=False)
            print(out_con.modified_count, out_con.raw_result)

            response_obj = {'status': 'updated'}
        else:
            result = "not updated"
            response_obj = {'status': result}

        '''
        elif data['name'] =='history':

            logger.info('enter history')
            add_name = data['history']
            ip_query = {'deviceip': data['device_ip']}
            out = cam_list.find_one(ip_query)
            x = out['programhistory']
            array_his = []
            if len(x) != 0:
                if add_name in x:
                    logger.info('true')
                else:
                    logger.info('new update')
                    x.append(add_name)
                    x.remove("")
                    update = {'programhistory': x}
                    cam_list.update_one(ip_query, {"$set": update}, upsert=False)
            else:
                array_his.append(add_name)
                array_his.remove("")
                logger.info('new update')
                update = {'programhistory': array_his}
                cam_list.update_one(ip_query, {"$set": update}, upsert=False)

            response_obj = {'status': 'updated'}
        elif data['name'] == 'programstatus':  # download new program
            logger.info('programstatus')
            st = data['programstatus']
            update = {'programstatus': st}
            cam_list.update_one({'deviceip': data['device_ip']}, {"$set": update}, upsert=False)
            response_obj = {'status': 'updated'}'''

        return web.json_response(response_obj)
    except Exception as e:
        response_obj = {'status': 'failed', 'reason': str(e)}
        print(response_obj)
        return web.json_response(response_obj)


async def program_configGroup(request):
    print("____________________________progrm config")
    out_data = await request.json()

    cameraDB = management['camera']

    if 'cameraGroup' in out_data:
        cameraGroup = out_data['cameraGroup']
    else:
        cameraGroup = False

    client_ip = out_data['ip']
    cameraip = out_data['cameraip']
    cameraname = out_data['cameraname']
    userId = out_data['userId']
    if cameraGroup:
        query_list = [{'deviceip': client_ip}, {'userId': userId}]
    else:
        query_list = [{'deviceip': client_ip}, {'cameraip': cameraip}, {'cameraname': cameraname}, {'userId': userId}]

    details_cam = cameraDB.find({'$and': query_list},
                                {'_id': 0, 'programhistory': 0, 'associate': 0, 'location': 0, 'devicename': 0,
                                 'name': 0, 'datetime': 0, 'programs': 0, 'intrusioncanvas': 0, 'intrusionImageUrl': 0,
                                 'templeteImage': 0})
    finalCam = []
    for camInfo in details_cam:
        finalCam.append(camInfo)

    print(finalCam)

    return web.json_response(finalCam)


async def uploadTemplate(request):
    out_data = await request.json()
    try:
        jpg_as_text = out_data['datapoint']
        programName = out_data['programName']
        Fname = out_data['name']
        nparr = np.fromstring(base64.b64decode(jpg_as_text), np.uint8)
        img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        baspathS = os.path.join(management_path, 'server', 'video')
        save_path = os.path.join(baspathS, programName)
        if os.path.isdir(save_path):
            pass
        else:
            os.makedirs(save_path)
        savePathFinal = os.path.join(save_path, Fname)
        cv2.imwrite(savePathFinal, img_final)
        output_res = {}
        output_res['result'] = 'success'
    except Exception as e:
        logger.info("uploadTemplate: " + str(e))
        output_res = {}
        output_res['result'] = 'failed'

    return web.Response(text=json.dumps(output_res), status=200)


programs = management['programs']


async def getpem(request):
    out_data = await request.json()
    print("pem", out_data)
    dspem = programs.find_one(
        {"section": out_data['section']},
        {'program-list': {'$elemMatch': {'name': out_data['programname']}}});

    finaldata = dspem['program-list'][0]['data']

    output_res = {"data": finaldata}

    return web.Response(text=json.dumps(output_res), status=200)


if __name__ == '__main__':
    head, tail = os.path.split(__file__)
    filename = os.path.splitext(tail)[0]
    # app = web.Application()
    app = web.Application(client_max_size=server_details['client_max'] ** 2)
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })
    cors.add(app.router.add_post('/systemregistry', systemregistry))
    cors.add(app.router.add_post('/critical', critical))
    cors.add(app.router.add_post('/event', event))
    cors.add(app.router.add_post('/alert_face', alert_face))
    cors.add(app.router.add_post('/alert_face_magnum', alert_face_magnum))
    cors.add(app.router.add_post('/updation_done', updation_done))
    cors.add(app.router.add_post('/program_config', program_config))
    cors.add(app.router.add_post('/get_sys_reg', get_sys_reg))
    cors.add(app.router.add_post('/get_event', get_event))
    cors.add(app.router.add_post('/get_critical', get_critical))
    cors.add(app.router.add_post('/get_criminaldb', get_criminaldb))
    cors.add(app.router.add_post('/get_criminaldb_magnum', get_criminaldb_magnum))
    cors.add(app.router.add_post('/get_collections', get_collections))
    cors.add(app.router.add_post('/users/register', register))
    cors.add(app.router.add_post('/users/login', login))
    cors.add(app.router.add_post('/users/logout_mobile', logout_mobile))
    cors.add(app.router.add_post('/allUsers', allUsers))
    cors.add(app.router.add_post('/get_superadmin', get_superadmin))
    cors.add(app.router.add_post('/allRoles', allRoles))
    cors.add(app.router.add_post('/createRole', createRole))
    cors.add(app.router.add_post('/deleteRole', deleteRole))
    cors.add(app.router.add_post('/deleteUser', deleteUser))
    cors.add(app.router.add_post('/allPages', allPages))
    cors.add(app.router.add_post('/getUserRoles', getUserRoles))
    cors.add(app.router.add_post('/cameralist', cameralist))
    cors.add(app.router.add_post('/cameralistAll', cameralistAll))
    cors.add(app.router.add_post('/cameralistAll1', cameralistAll1))
    cors.add(app.router.add_post('/updateSelectedProgram', updateSelectedProgram))
    cors.add(app.router.add_post('/updateProgramList', updateProgramList))
    cors.add(app.router.add_post('/deleteProgramList', deleteProgramList))
    cors.add(app.router.add_post('/deleteCriminalFace', deleteCriminalFace))
    cors.add(app.router.add_post('/deleteCamera', deleteCamera))
    cors.add(app.router.add_post('/updateCameras', updateCameras))
    cors.add(app.router.add_post('/deleteCriminalList', deleteCriminalList))
    cors.add(app.router.add_post('/deleteCameraList', deleteCameraList))
    cors.add(app.router.add_post('/program_status_management', program_status_management))
    cors.add(app.router.add_post('/updateProgramSS', updateProgramSS))
    cors.add(app.router.add_post('/updateExeStartStopStatus', updateExeStartStopStatus))
    cors.add(app.router.add_post('/updateCoOrdinates', updateCoOrdinates))
    cors.add(app.router.add_post('/groupList', groupList))
    cors.add(app.router.add_post('/groupListAll', groupListAll))
    cors.add(app.router.add_post('/updateCoOrdinatesTest', updateCoOrdinatesTest))
    cors.add(app.router.add_post('/addGroupList', addGroupList))
    cors.add(app.router.add_post('/updateZonedFloorPlan', updateZonedFloorPlan))
    cors.add(app.router.add_post('/getZonedFloorPlan', getZonedFloorPlan))
    cors.add(app.router.add_post('/getZonedFloorPlanAll', getZonedFloorPlanAll))
    cors.add(app.router.add_post('/getZonedFloorPlanbyname', getZonedFloorPlanbyname))
    cors.add(app.router.add_post('/updateIntrusionPlan', updateIntrusionPlan))
    cors.add(app.router.add_post('/getSavedIntrusions', getSavedIntrusions))
    cors.add(app.router.add_post('/saveMapData', saveMapData))
    cors.add(app.router.add_post('/getMapPlan', getMapPlan))
    cors.add(app.router.add_post('/camerabyCameraIP', camerabyCameraIP))
    cors.add(app.router.add_post('/programlist', programlist))
    cors.add(app.router.add_post('/updateVerifiedAlert', updateVerifiedAlert))
    cors.add(app.router.add_post('/approvalList', approvalList))
    cors.add(app.router.add_post('/updateRequest', updateRequest))
    cors.add(app.router.add_post('/visitorsList', visitorsList))
    cors.add(app.router.add_post('/approveRequest', approveRequest))
    cors.add(app.router.add_post('/updateVisitorRegisteredImage', updateVisitorRegisteredImage))
    cors.add(app.router.add_post('/serverCheck', serverCheck))
    cors.add(app.router.add_post('/port_check', port_check))
    cors.add(app.router.add_post('/deleteAlerts', deleteAlerts))
    cors.add(app.router.add_post('/get_encode_list', get_encode_list))
    cors.add(app.router.add_post('/get_encode_list_mangnum', get_encode_list_mangnum))
    cors.add(app.router.add_post('/updateLicenseRequest', updateLicenseRequest))
    cors.add(app.router.add_post('/updateLicense', updateLicense))
    cors.add(app.router.add_post('/updatePortalLicenseRequest', updatePortalLicenseRequest))
    cors.add(app.router.add_post('/updatePortalLicense', updatePortalLicense))
    # cors.add(app.router.add_post('/license_Validation', license_Validation))
    cors.add(app.router.add_post('/deletePlan', deletePlan))
    cors.add(app.router.add_post('/updatePortalNotification', updatePortalNotification))
    cors.add(app.router.add_post('/get_system_address', get_system_address))
    cors.add(app.router.add_post('/getUsersByDepartment', getUsersByDepartment))
    cors.add(app.router.add_post('/getAlertsLatest', getAlertsLatest))
    cors.add(app.router.add_post('/getAlertsLatestAlpr', getAlertsLatestAlpr))
    cors.add(app.router.add_post('/getAlertsLatestAlprByCamera', getAlertsLatestAlprByCamera))
    cors.add(app.router.add_post('/getAlerts', getAlerts))
    cors.add(app.router.add_post('/getAlertsByDate', getAlertsByDate))
    cors.add(app.router.add_post('/getMaskAlertsByDate', getMaskAlertsByDate))
    cors.add(app.router.add_post('/getPpeAlertsByDate', getPpeAlertsByDate))
    cors.add(app.router.add_post('/getCapAlertsByDate', getCapAlertsByDate))
    cors.add(app.router.add_post('/getProdAlertsByDate', getProdAlertsByDate))

    cors.add(app.router.add_post('/getProdAlertsBySummary', getProdAlertsBySummary))
    cors.add(app.router.add_post('/getqueueAlertsByDate', getqueueAlertsByDate))

    cors.add(app.router.add_post('/getqueueAlertsBySummary', getqueueAlertsBySummary))
    cors.add(app.router.add_post('/getPeopleAlertsByDate', getPeopleAlertsByDate))
    cors.add(app.router.add_post('/getPeopleAlertsBySummary', getPeopleAlertsBySummary))
    cors.add(app.router.add_post('/getAnalyticsAlertsBySummary', getAnalyticsAlertsBySummary))

    cors.add(app.router.add_post('/getAlertsBetweenDates', getAlertsBetweenDates))
    cors.add(app.router.add_post('/getAlertById', getAlertById))
    cors.add(app.router.add_post('/get_template_snap', get_template_snap))
    cors.add(app.router.add_post('/crop_template', crop_template))
    cors.add(app.router.add_post('/updateFiatCoOrdinatesTest', updateFiatCoOrdinatesTest))
    cors.add(app.router.add_post('/getAlertsCanvas', getAlertsCanvas))
    cors.add(app.router.add_post('/createTraining', createTraining))
    cors.add(app.router.add_post('/getSavedTraining', getSavedTraining))
    cors.add(app.router.add_post('/updateTrainingModel', updateTrainingModel))
    cors.add(app.router.add_post('/upload_register', upload_register))
    cors.add(app.router.add_post('/get_alert_details', get_alert_details))
    cors.add(app.router.add_post('/getStatus', getStatus))
    cors.add(app.router.add_post('/getStatusByName', getStatusByName))
    cors.add(app.router.add_post('/updateStatusSS', updateStatusSS))
    cors.add(app.router.add_post('/getAlignmentProjects', getAlignmentProjects))
    cors.add(app.router.add_post('/updateAlignmentCoOrdinatesTest', updateAlignmentCoOrdinatesTest))
    cors.add(app.router.add_post('/updateAlignmentCoOrdinatesTest1', updateAlignmentCoOrdinatesTest1))

    cors.add(app.router.add_post('/getFaceAlerts', getFaceAlerts))
    cors.add(app.router.add_post('/alert_general', alert_general))
    cors.add(app.router.add_post('/alert_general_peoplecount', alert_general_peoplecount))

    cors.add(app.router.add_post('/get_encode_list_general', get_encode_list_general))
    cors.add(app.router.add_post('/get_criminaldb_count', get_criminaldb_count))
    cors.add(app.router.add_post('/getSysregByIp', getSysregByIp))
    cors.add(app.router.add_post('/getFaceAlertsByName', getFaceAlertsByName))
    cors.add(app.router.add_post('/checkEncodeDum', upload_encode_db_full))
    cors.add(app.router.add_post('/check_gitter', check_gitter))
    cors.add(app.router.add_post('/getAlertsByMonth', getAlertsByMonth))
    cors.add(app.router.add_post('/all_program_list', all_program_list))
    cors.add(app.router.add_post('/allProgramListbySection', allProgramListbySection))
    cors.add(app.router.add_post('/updateCameraUrl', updateCameraUrl))
    cors.add(app.router.add_post('/updateCameraStatus', updateCameraStatus))
    cors.add(app.router.add_post('/updateTestStatus', updateTestStatus))
    cors.add(app.router.add_post('/getLicenseInformation', getLicenseInformation))
    cors.add(app.router.add_post('/updateDeviceLicenseRequest', updateDeviceLicenseRequest))
    cors.add(app.router.add_post('/updateCameraLicenseRequest', updateCameraLicenseRequest))
    cors.add(app.router.add_post('/updateDeviceLicense', updateDeviceLicense))
    cors.add(app.router.add_post('/updateDeviceLicenseData', updateDeviceLicenseData))
    cors.add(app.router.add_post('/alert_demo', alert_demo))
    cors.add(app.router.add_post('/allProgrambySectionProgram', allProgrambySectionProgram))
    cors.add(app.router.add_post('/program_config_demo', program_config_demo))
    # cors.add(app.router.add_post('/program_config_mulity', program_config_mulity))
    cors.add(app.router.add_post('/updation_doneGroup', updation_doneGroup))
    cors.add(app.router.add_post('/program_configGroup', program_configGroup))
    cors.add(app.router.add_post('/alertOffline', alertOffline))
    cors.add(app.router.add_post('/uploadTemplate', uploadTemplate))
    cors.add(app.router.add_post('/getpem', getpem))
    cors.add(app.router.add_post('/get_camstatus', get_camstatus))

    cors.add(app.router.add_post('/getVehicleData', getVehicleData))
    cors.add(app.router.add_post('/getVehicleDataByNumber', getVehicleDataByNumber))
    cors.add(app.router.add_post('/updateVehicle', updateVehicle))
    cors.add(app.router.add_post('/updateVehicleExcel', updateVehicleExcel))
    cors.add(app.router.add_post('/updateProgramConfig', updateProgramConfig))

    web.run_app(app, port=port)