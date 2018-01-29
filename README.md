# Item Catalog Web App
This web app is a project for the Udacity [Full Stack Developer Nanodegree](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004).

## About
The Item Catalog project consists of developing an application that provides a list of items within a variety of categories, as well as a user registration and authentication system. This project uses persistent data storage to create a RESTful web application that allows users to perform Create, Read, Update, and Delete operations.

A user does not need to be logged in to view the categories or items. However, users who created an item are the only users allowed to update or delete the item that they created.

This program uses third-party auth with Google or Facebook. Some of the technologies used to build this application include Flask, jQuery, MaterializeCSS, Jinja2, and SQLite.

## In This Repo
This project has one main Python module `views.py` which runs the Flask application. A SQL database is created using the `database_setup.py` module and you can populate the database with test data using `defaultcatalog.py`.
The Flask application uses stored HTML templates in the tempaltes folder to build the front-end of the application. CSS/JS/Images are stored in the static directory.

## Skills Honed
1. Python
2. HTML
3. CSS
4. JS
5. OAuth
6. Flask Framework
7. jQuery Framework
8. AJAX
9. Web Security

## Extra Credit Description
The following features were implemented to gain an extra credit from Udacity:

* Added Image Upload with preview functionality
* Added Full Text Search functionality
* Added anti Cross-Site Request Forgery (CSRF) to protect the app from CSRF attacks
* Using AJAX to submit forms resulting in a increased user experience as pages are not reloaded on submit
* Mobile-friendly design (full responsive)

## Installation
There are some dependancies and a few instructions on how to run the application.

## Dependencies
- [Vagrant](https://www.vagrantup.com/)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

## How to Install
1. Install Vagrant & VirtualBox
2. Clone this repo
3. Git-Bash into the clones repo
4. Launch the Vagrant VM (`vagrant up`)
5. Log into Vagrant VM (`vagrant ssh`)
6. Navigate to `cd /vagrant` as instructed in terminal
7. The app imports Requests which is not on this vm. Run sudo pip install requests
8. The app imports WTForms which is not on this vm. Run sudo pip install WTForms
9. Setup application database `python database_setup.py`
10. *Insert fake data `python defaultcatalog.py`
11. Run application using `python views.py`
12. Access the application locally using http://localhost:5000

*Optional step

## JSON Endpoints
The following are open to the public:

Catalog JSON: `/catalog.json/`
    - Displays the whole catalog. Categories and all items.

Items JSON: `/items.json/`
    - Displays all items.

## Miscellaneous
This README document is based on the excellent template used by gmawji in this [repo](https://github.com/gmawji/item-catalog).
