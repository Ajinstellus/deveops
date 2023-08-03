import cv2
import numpy as np
import os
import face_recognition
from datetime import datetime
import csv
from ApI import send_alert
import sys
sys.path.append('ApI.py')
import json



path = r"/home/cogvision/Documents/Attendance_management"

images = []
classnames = []
mylist = os.listdir(path)

for cl in mylist:
    curImg = cv2.imread(f'{path}/{cl}')
    images.append(curImg)
    classnames.append(os.path.splitext(cl)[0])


def findEncodings(images):
    encodeList = []
    for img in images:
        img = cv2.cvtColor(img,cv2.COLOR_BGR2RGB)
        encode = face_recognition.face_encodings(img)[0]
        encodeList.append(encode)

    return encodeList

encodeListKnown = findEncodings(images)
print('encoding complete')


cap = cv2.VideoCapture(0)

csv_filename = 'recognized_faces.csv'
header = ['NAME', 'TIME']
with open(csv_filename, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)

while True:
    success, img = cap.read()
    if not success:
        break

    faceCurFrame = face_recognition.face_locations(img)
    encodeCurFrame = face_recognition.face_encodings(img, faceCurFrame)

    for encodeface, faceloc in zip(encodeCurFrame, faceCurFrame):
        matches = face_recognition.compare_faces(encodeListKnown, encodeface)
        faceDis = face_recognition.face_distance(encodeListKnown, encodeface)
        matchIndex = np.argmin(faceDis)
        #print(encodeface)

        if matches[matchIndex]:
            name = classnames[matchIndex].upper()
            y1, x2, y2, x1 = faceloc
            cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.rectangle(img, (x1, y2 - 35), (x2, y2), (0, 255, 0), cv2.FILLED)
            cv2.putText(img, name, (x1 + 6, y2 - 6), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 2)

            current_time = datetime.now().strftime("%y-%m-%d %H:%M:%S")
            with open(csv_filename, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([name, current_time])


        else:
             name = "Unknown"
             cv2.rectangle(img, (x1, y1), (x2, y2), (0, 255, 0), 2)
             cv2.rectangle(img, (x1, y2 - 35), (x2, y2), (0, 255, 0), cv2.FILLED)
             cv2.putText(img, name, (x1 + 6, y2 - 6), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 2)





    cv2.imshow("webcam",img)
    if cv2.waitKey(1)&0xFF==ord('q'):
        break

cv2.destroyAllWindows()

