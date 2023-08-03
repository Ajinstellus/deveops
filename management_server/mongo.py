const express = require('express');
const MongoClient = require('mongodb').MongoClient;

const app = express();
const port = 8080;

app.use(express.json());
let database;

app.get('/', (req, res) => {
  res.send('Welcome to the MongoDB API');
});

// MongoDB connection and server initialization
const mongoURL = 'mongodb://localhost:27017'; // Replace 'localhost' with your MongoDB server address
const dbName = 'automotive-management'; // Replace with your desired database name

MongoClient.connect(mongoURL, { useNewUrlParser: true }, (err, client) => {
  if (err) {
    console.error('Error connecting to MongoDB:', err);
    return;
  }

  database = client.db(dbName);
  console.log('Connected to MongoDB successfully');

  // Start the server only after the MongoDB connection is established
  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
});