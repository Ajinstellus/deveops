import cv2
import numpy as np
import os
import face_recognition

img = face_recognition.load_image_file("/home/cogvision/Documents/Attendance_management/Sajin.jpg")
img = cv2.cvtColor(img,cv2.COLOR_BGR2RGB)
img1 = face_recognition.load_image_file("/home/cogvision/Documents/Attendance_management/ajin.jpg")
img1 = cv2.cvtColor(img1,cv2.COLOR_BGR2RGB)


faceloc = face_recognition.face_locations(img)[0]
faceencode = face_recognition.face_encodings(img)[0]
cv2.rectangle(img, (faceloc[3],faceloc[0]),(faceloc[1],faceloc[2]),(0,255,0),2)

faceloc1 = face_recognition.face_locations(img1)[0]
faceencode1 = face_recognition.face_encodings(img1)[0]
cv2.rectangle(img1, (faceloc1[3],faceloc1[0]),(faceloc1[1],faceloc1[2]),(0,255,0),2)

results = face_recognition.compare_faces([faceencode],faceencode1)
dis = face_recognition.face_distance([faceencode],faceencode1)
print(results,dis)

cv2.imshow("img",img)
cv2.imshow("img1",img1)
cv2.waitKey(0)
cv2.destroyAllWindows()

