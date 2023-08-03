from flask import Flask, jsonify
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://cogxar:*****@localhost:27017/?authMechanism=DEFAULT&authSource=cubix-management'  # Replace with your MongoDB connection URI
mongo = PyMongo(app)

@app.route('/', methods=['GET'])
def index():
    return 'Welcome to the API endpoint'

@app.route('/api/data', methods=['GET'])
def get_data():
    collection = mongo.db.camera  # Replace 'collection_name' with the actual name of your collection
    data = collection.find()  # Retrieve all documents from the collection
    result = []  # Empty list to store the retrieved data
    for doc in data:
        result.append({
            'id': str(doc['_id']),
            'name': doc['name'],
            'description': doc['description']
        })  # Customize the fields based on your document structure
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
