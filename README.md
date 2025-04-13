# Cloud-Storage-Application
Repository to store code for Assignment 2 of Advanced Computer Networks

# Pre-Requisites
You need to create a database before running the flask server
1. Navigate to the `backend` folder
2. Open a terminal in that directory and run `flask shell`
3. run the following commands
   `from app import db`
   `db.create_all()`
   `exit()`

If you choose to delete the table, run:
    `db.drop_all()`
⚠️ THIS DOES DELETE ALL OF YOUR DATA

# How to run
1. Navigate to directory where `app.py` resides
2. Open a terminal in that directory and run `flask run`
3. Follow the link in the terminal
