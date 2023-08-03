from flask import Flask, jsonify
import pymongo

app = Flask(__name__)

# MongoDB connection settings
mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo_client["alerts"]
collection = db["frs"]

@app.route('/alerts', methods=['GET'])
def get_alerts():
    alerts = list(collection.find({}, {'_id': 0}))  # Fetch all alerts from the 'frs' collection
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
