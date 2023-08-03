const express = require('express');
const mongodb = require('mongodb');
const app = express();

const mongoURI = 'mongodb://cogxar:*****@localhost:27017/?authMechanism=DEFAULT&authSource=cubix-management'; // Replace with your MongoDB connection URI
const dbName = 'automotive-management'; // Replace with your MongoDB database name
const collectionName = 'camera'; // Replace with your MongoDB collection name

// Define a route to fetch camera details
app.get('/api/camera-details', (req, res) => {
  // Connect to MongoDB
  mongodb.MongoClient.connect(mongoURI, { useUnifiedTopology: true }, (err, client) => {
    if (err) {
      console.error('Failed to connect to MongoDB:', err);
      res.status(500).json({ error: 'Failed to connect to MongoDB' });
      return;
    }

    // Access the database and collection
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    // Retrieve the camera details
    collection.find().toArray((err, cameraDetails) => {
      if (err) {
        console.error('Failed to fetch camera details:', err);
        res.status(500).json({ error: 'Failed to fetch camera details' });
        return;
      }

      // Return the camera details as the API response
      res.json(cameraDetails);
    });
  });
});

// Start the server
app.listen(5001, () => {
  console.log('Server is running on http://localhost:5001');
});
