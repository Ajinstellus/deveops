import cv2

img = cv2.imread("/home/cogvision/Downloads/IMG_20200404_122954.jpg")
img = cv2.resize(img,(600,600))
#cv2.imwrite("/home/cogvision/Documents/Attendance_management/sajin.jpg",img)

cv2.imshow("img",img)
cv2.waitKey(0)