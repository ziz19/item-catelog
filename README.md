# item-catelog

This application  provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

## Prerequisite
  Python 2.7.X
  
  Vagrant installed

## Run this program
  1.  open up a terminal/shell/command line prompt,  `cd item-catelog` into the project repository
  2. `vagrant up` to start the virtual machine. The vagrant configuration file is already in the project
  3. `vagrant ssh` to connect to the virtual machine
  4. `cd /vagrant/` to the project repo which is now mapped to the **vagarnt** folder
  5. (optional) if this is the first time you run, `python database_setup.py` to initialize an empty database for your catalog
  6. `python project.py` to run a local server
  7. open your favourite browser, type in [localhost:5000/](localhost:5000/) or [localhost:5000/catalog/](localhost:5000/catalog/)
  8. Now you can view the existing catalog, or modify them after loging into your Google account 
