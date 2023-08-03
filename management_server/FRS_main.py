import cv2
import os
import numpy as np
import face_recognition

path = r"/home/cogvision/Documents/Attendance_management"
images = []
classnames = []
mylist = os.listdir(path)
#print(mylist)

for cl in mylist:
    curImg = cv2.imread(f"{path}/{cl}")
    images.append(curImg)
    classnames.append(os.path.splitext(cl)[0])
#print(classnames)

def findEnccodings(images):
    encodeList = []
    for img in images:
        img = cv2.cvtColor(img,cv2.COLOR_BGR2RGB)
        encode = face_recognition.face_encodings(img)[0]
        encodeList.append(encode)
    return encodeList

encodeListKnown = findEnccodings(images)
print('encoding complete')

cap = cv2.VideoCapture(0)

while True:
    sucess, imgs=cap.read()
    #imgs = cv2.cvtColor(imgs,cv2.COLOR_BGR2RGB)
    facesCurFrame = face_recognition.face_locations(imgs)
    encodeCurFrame = face_recognition.face_encodings(imgs, facesCurFrame)

    for encodeFace, faceLoc in zip(encodeCurFrame, facesCurFrame):
        matches = face_recognition.compare_faces(encodeListKnown,encodeFace)
        facedis = face_recognition.face_distance(encodeListKnown, encodeFace)
        #print(facedis)
        matchIndex = np.argmin(facedis)
        #print(matchIndex)

        if matches[matchIndex]:
            name = classnames[matchIndex].upper()
            y1,x2,y2,x1 = faceLoc
            cv2.rectangle(imgs, (x1,y1), (x2,y2), (0,255,0), 2)
            cv2.rectangle(imgs, (x1, y2 - 35), (x2, y2), (0, 255, 0), cv2.FILLED)
            cv2.putText(imgs,name,(x1 + 6, y2 - 6), cv2.FONT_HERSHEY_COMPLEX, 1, (255,255,255), 2)

        else:
            name = "Unknown"
            cv2.rectangle(imgs, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.rectangle(imgs, (x1, y2 - 35), (x2, y2), (0, 255, 0), cv2.FILLED)
            cv2.putText(imgs, name, (x1 + 6, y2 - 6), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 2)

    cv2.imshow("webcam",imgs)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cv2.destroyAllWindows()








