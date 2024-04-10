const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const dotenv = require('dotenv'); // Import dotenv package

dotenv.config(); // Load environment variables from .env file

const app = express();

const dbPath = path.join(__dirname, 'travelBlog.db');
let db = null;

const initializeDatabase = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database
    });

    const port = process.env.PORT || 5000; // Use port from environment variable or default to 5000

    app.listen(port, () => {
      console.log(`Server is up and running at the port ${port} ra mawa`);
    });
  } catch (e) {
    console.log(`DB Error vachindi mawa: ${e.message}`);
    process.exit(1);
  }
}

initializeDatabase();

// Rest of your code...


app.use(express.json())

// register user api

app.post('/users/', async (request, response) => {
  const { username, password, email } = request.body
  const hashedPassword = await bcrypt.hash(password, 10)
  const selectUserQuery = 'SELECT * FROM users WHERE username = ?'

  try {
    const dbUser = await db.get(selectUserQuery, [username])

    if (dbUser === undefined) {
      const createUserQuery =
        'INSERT INTO users(username,password,email) VALUES (?,?,?)'

      // Run the INSERT query and retrieve last inserted row ID using lastID attribute
      const dbResponse = await db.run(createUserQuery, [
        username,
        hashedPassword,
        email
      ])
      const newID = dbResponse.lastID
      response.send(`created new user with id ${newID}`)
    } else {
      response.status(400).send('Username already exists')
    }
  } catch (error) {
    console.error('Error registering user:', error)
    response.status(500).send('Error registering user')
  }
})

// logging in the user
app.post('/login/', async (request, response) => {
  const { username, password } = request.body
  const selectUserQuery = 'SELECT * FROM users WHERE username = ?'

  try {
    const dbUser = await db.get(selectUserQuery, [username])

    if (!dbUser) {
      response.status(400).send('Invalid User')
    } else {
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password)

      if (isPasswordMatched) {
        const payload = {
          username: username
        }

        const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
        response.send({ jwtToken })
      } else {
        response.status(400).send('Invalid Password')
      }
    }
  } catch (error) {
    console.error('Error logging in user:', error)
    response.status(500).send('Error logging in user')
  }
})

// creating a middleware function for token verification
const authenticateToken = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']

  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }

  if (jwtToken === undefined) {
    response.status(401).send('invalid jwt token')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401).send('Inavlid JWT Token')
      } else {
        next()
      }
    })
  }
}

app.put(
  '/update_profile/:userId',
  authenticateToken,
  async (request, response) => {
    const { userId } = request.params

    const { username, password, email } = request.body

    // Use parameterized query to prevent SQL injection
    const updateProfileQuery = `UPDATE users 
                              SET username = ?, password = ?, email = ? 
                              WHERE id = ?`

    try {
      const dbResponse = await db.run(updateProfileQuery, [
        username,
        password,
        email,
        userId
      ])
      console.log(dbResponse)
      response.send('Profile updated successfully')
    } catch (error) {
      console.error('Error updating profile:', error.message)
      response.status(500).send('Error updating profile')
    }
  }
)

// get a diary entry
app.get('/entries/', authenticateToken, async (request, response) => {
  const getDairyEntry = `SELECT * FROM Entry order by EntryID;`
  const diaryEntryArray = await db.all(getDairyEntry)

  response.send(diaryEntryArray)
})

// get a diary entry by id
// response return entryid at put method
app.get('/entries/:entryId', authenticateToken, async (request, response) => {
  const { entryId } = request.params

  const getDairyEntry = `SELECT * FROM Entry where EntryID = ${entryId}`

  const dbResponse = await db.all(getDairyEntry)

  response.send(dbResponse)
})

// get a entry by user id
app.get(
  '/entries_by_user/:userId',
  authenticateToken,
  async (request, response) => {
    const { userId } = request.params

    // Use parameterized queries to prevent SQL injection
    const getDairyEntry = `SELECT * FROM Entry WHERE UserID = ?`

    try {
      const dbResponse = await db.all(getDairyEntry, [userId])
      response.send(dbResponse)
    } catch (error) {
      console.error('Error fetching entries by user:', error.message)
      response.status(500).send('Error fetching entries by user')
    }
  }
)

// creating a new entry
app.post('/diary_entries/', authenticateToken, async (request, response) => {
  try {
    const { title, content, date, location, UserID } = request.body

    // Insert data into the diary_entries table
    const dbResponse = await db.run(
      'INSERT INTO Entry (title, content, date, location, UserID) VALUES (?, ?, ?, ?, ?)',
      [title, content, date, location, UserID]
    )

    const newID = dbResponse.lastID

    response
      .status(201)
      .send(`Diary entry created successfully with id ${newID} `)
  } catch (error) {
    console.error('Error creating diary entry:', error)
    response.status(500).send('Error creating diary entry')
  }
})

// updating an entry

app.put(
  '/update_entry/:entryId',
  authenticateToken,
  async (request, response) => {
    const { entryId } = request.params
    const { title, content, date, location } = request.body

    // Use parameterized queries to prevent SQL injection
    const updateEntry = `UPDATE Entry 
                         SET title = ?, content = ?, date = ?, location = ? 
                         WHERE EntryID = ?`

    try {
      const dbResponse = await db.run(updateEntry, [
        title,
        content,
        date,
        location,
        entryId
      ])
      console.log(dbResponse)
      response.send('Entry updated successfully')
    } catch (error) {
      console.error('Error updating entry:', error.message)
      response.status(500).send('Error updating entry')
    }
  }
)

app.delete(
  '/delete_entry/:entryId',
  authenticateToken,
  async (request, response) => {
    const { entryId } = request.params

    // Use parameterized query to prevent SQL injection
    const deleteEntry = `DELETE FROM Entry WHERE EntryID = ?`

    try {
      const dbResponse = await db.run(deleteEntry, [entryId])
      console.log(dbResponse)
      response.send('Entry deleted successfully')
    } catch (error) {
      console.error('Error deleting entry:', error.message)
      response.status(500).send('Error deleting entry')
    }
  }
)
