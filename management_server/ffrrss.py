import cv2
import dlib
import face_recognition
import pymongo

# MongoDB setup
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["alert"]
collection = db["faces"]

# Load registered face encodings from MongoDB
registered_faces = []
for record in collection.find():
    registered_faces.append(face_recognition.face_encodings(record["image"])[0])

# Load face detector
face_detector = dlib.get_frontal_face_detector()


# Function to recognize faces from video frames
def recognize_faces(frame):
    # Convert frame to RGB (face_recognition uses RGB images)
    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    # Detect faces in the frame
    face_locations = face_detector(rgb_frame)

    # Get face encodings for detected faces
    face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

    # Loop through detected faces
    for face_encoding, face_location in zip(face_encodings, face_locations):
        # Check if the detected face matches any registered face
        matches = face_recognition.compare_faces(registered_faces, face_encoding)

        # If a match is found, get the name from the database
        if True in matches:
            matched_index = matches.index(True)
            name = collection.find()[matched_index]["name"]
        else:
            name = "Unknown"

        # Draw a rectangle around the face and display the name
        top, right, bottom, left = face_location
        cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)
        font = cv2.FONT_HERSHEY_DUPLEX
        cv2.putText(frame, name, (left + 6, bottom - 6), font, 0.5, (255, 255, 255), 1)

    return frame


# Video processing
video_capture = cv2.VideoCapture(0)  # Replace with your video path or camera index (0 for webcam)
while True:
    ret, frame = video_capture.read()
    if not ret:
        break

    frame = recognize_faces(frame)

    cv2.imshow("Facial Recognition", frame)
    if cv2.waitKey(1) & 0xFF == ord("q"):
        break

video_capture.release()
cv2.destroyAllWindows()
