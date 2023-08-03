import cv2
import numpy as np
import face_recognition
import os
import pymongo
from datetime import datetime

mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo_client["alerts"]
collection = db["frs"]

path = r"/home/cogvision/Documents/Attendance_management"
images = []
classnames = []
mylist = os.listdir(path)

for cl in mylist:
    curImg = cv2.imread(f"{path}/{cl}")
    images.append(curImg)
    classnames.append(os.path.splitext(cl)[0])

def findEncodings(images):
    encodeList= []
    for img in images:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        encode = face_recognition.face_encodings(img)[0]
        encodeList.append(encode)
    return encodeList

encodeListknown = findEncodings(images)
print('encoding complete')

cap = cv2.VideoCapture(0)

while True:
    sucess, imgs = cap.read()
    facecurframe = face_recognition.face_locations(imgs)
    encodecurframe = face_recognition.face_encodings(imgs, facecurframe)

    for faceloc, encodeface in zip (facecurframe, encodecurframe):
        matches = face_recognition.compare_faces(encodeListknown, encodeface)
        facedis = face_recognition.face_distance(encodeListknown, encodeface)
        matchIndex = np.argmin(facedis)

        if matches[matchIndex]:
            name = classnames[matchIndex].upper()
            y1,x2,y2,x1 = faceloc
            cv2.rectangle(imgs, (x1,y1), (x2,y2), (0,255,0),2)
            cv2.rectangle(imgs, (x1, y2 - 35), (x2,y2), (0,255,0),cv2.FILLED)
            cv2.putText(imgs, name, (x1 + 6, y2 - 6),cv2.FONT_HERSHEY_COMPLEX, 1, (255,255,255),2)

            alert_image_filename = f"{name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"
            alert_image_path = os.path.join("/home/cogvision/Desktop/alrts", alert_image_filename)
            cv2.imwrite(alert_image_path, imgs)

            alert_data = {
                "name": name,
                "time_stamp": datetime.now(),
                "image_filename": alert_image_filename,
            }
            collection.insert_one(alert_data)

        else:
            name = "Unknown"
            cv2.rectangle(imgs, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.rectangle(imgs, (x1, y2 - 35), (x2, y2), (0, 255, 0), cv2.FILLED)
            cv2.putText(imgs, name, (x1 + 6, y2 - 6), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 2)

    cv2.imshow("webcam", imgs)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cv2.destroyAllWindows()







