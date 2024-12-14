const express = require('express');
const app = express();
const port = 6000;

app.get('/', (req, res) => {
  res.send('Hello!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
