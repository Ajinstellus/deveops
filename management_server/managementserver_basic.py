import base64
import os
import shutil
import uuid
import xlrd
import cv2
import numpy as np
def get_coll_name(find_name,alertdata_db):

    get_info = alertdata_db['info']
    list_count_size = get_info.count()

    qu = {"id": find_name}
    if get_info.find_one(qu):
        pass
    else:

        build_list = {}
        build_list['id'] = find_name
        build_list['name'] = find_name + "_1"
        get_info.insert_one(build_list)

    myquery = {"id": find_name}
    mydoc = get_info.find_one(myquery)
    get_name = mydoc['name']
    return (get_name)

def update_to_info(new_name,id,alertdata_db):

    get_info = alertdata_db['info']
    myquery = {"id": id}
    newvalues = {"$set": {"name": new_name}}
    get_info.update_one(myquery, newvalues)
    return 'updated'
def update_status(name,mongo_db):
    try :
        cubix_mangement = mongo_db['cubix-management']
        camera = cubix_mangement['camera']
        details_cam = camera.find({})
        for document in details_cam:
            program = document['selectedprogram']
            #logger.info(program)
            if name in program:
                update = {'status': 'true'}
                deviceip = document['deviceip']
                camera.update_one({'deviceip': deviceip}, {"$set": update}, upsert=False)
        out = "done"
    except:
        out = "failed"
    return out

def get_name(find_name,mongo_db):

    alertdata_db = mongo_db['alert']
    get_info = alertdata_db['info']
    myquery = {"id": find_name}
    mydoc = get_info.find_one(myquery)
    if mydoc:
        get_name = mydoc['name']
    else:
        get_name = ''
    return get_name

def readxl(foldername):
    sheet_data = []
    xlxpath = ''
    for fname in os.listdir(foldername):
        if fname.endswith('.xlsx'):
            #logger.info(fname)
            xlxpath = os.path.join(foldername,fname)
            wb = xlrd.open_workbook(xlxpath)
            sh = wb.sheet_by_name('Sheet1')
            for rownum in range(sh.nrows):
                sheet_data.append((sh.row_values(rownum)))
            break
    return sheet_data,xlxpath

def get_count(foldername):
    count_dir = len(os.listdir(foldername))
    return count_dir
def search_in_data(filename,xldata):
    Description = ''
    region =''
    name =''
    for i in xldata:
        if i[3] == filename:
            Description = i[1]
            region = i[2]
            name = i[0]
            break
        else:
            Description = ''
            region =''
            name =''
    return Description , region,name
def move_file(new_dir,filderpath,filenames):
    #logger.info(filenames)
    if os.path.isdir(new_dir):
        pass
    else:
        os.mkdir(new_dir)

    current_path = os.path.join(filderpath, filenames)
    new_dir_path = os.path.join(new_dir, filenames)
    shutil.move(current_path, new_dir_path)
def refined_box(left, top, width, height):
    right = left + width
    bottom = top + height

    original_vert_height = bottom - top
    top = int(top + original_vert_height * 0.15)
    bottom = int(bottom - original_vert_height * 0.05)

    margin = ((bottom - top) - (right - left)) // 2
    left = left - margin if (bottom - top - right + left) % 2 == 0 else left - margin - 1

    right = right + margin

    return left, top, right, bottom

def get_image(found_list,name_alert,management_path):
    if found_list['image_points'] != '':
        nparr = np.fromstring(base64.b64decode(found_list['image_points']), np.uint8)
        img_final = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        alert_img_path = os.path.join(management_path,'public','alert',name_alert)
        save_name = os.path.join(alert_img_path, found_list['imagename'])
        if os.path.isdir(alert_img_path):
            pass
        else:
            os.makedirs(alert_img_path)

        print(save_name)
        cv2.imwrite(save_name,img_final)
    else:
        print("data empty")

    return "done"

def create_name_alert(name_alert,alertdata_db,logger):
    try:
        last_updated_name = get_coll_name(name_alert,alertdata_db)
        st = alertdata_db.command("collstats", last_updated_name)
    except:
        st = {}
        st['size'] = 0
    size  = st['size'] / 1024

    if size >1000:
        split_name = last_updated_name.split("_")
        count = int(split_name[len(split_name)-1])
        new_nzme= '_'.join(split_name[:len(split_name)-1])
        newname =new_nzme +'_'+str(count+1)
        name_doc = newname
        print(name_doc)
        update_to_info(newname,name_alert,alertdata_db)
    else:
        name_doc = last_updated_name
    logger.info('size :' + str(size))
    logger.info(name_doc)
    return name_doc




def get_address():
    address = hex(uuid.getnode())
    return address
