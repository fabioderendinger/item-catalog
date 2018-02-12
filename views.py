import os

# to generate unique filenames for the uploaded and stored images
import tempfile

from flask import (Flask, render_template, request, redirect,
                   jsonify, url_for, flash, g, abort, escape)
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from werkzeug.utils import secure_filename
from flask import send_from_directory

from wtforms import (Form, StringField, HiddenField,
                     TextAreaField, SelectField, FileField, validators)
from wtforms.validators import DataRequired, Regexp

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token (CSRF Token)
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Definition of Forms
class CreateCategoryForm(Form):
    c_cat_name = StringField('Category', validators=[DataRequired()])
    c_cat_csrf_token = HiddenField('csrf_token', validators=[DataRequired()])


class DeleteCategoryForm(Form):
    d_cat_id = HiddenField('Category ID', validators=[DataRequired()])
    d_active_cat_id = HiddenField('Active Category ID')
    d_cat_csrf_token = HiddenField('csrf_token', validators=[DataRequired()])


class UpdateCategoryForm(Form):
    u_cat_name = StringField('Category', validators=[DataRequired()])
    u_cat_id = HiddenField('Category ID', validators=[DataRequired()])
    u_active_cat_id = HiddenField('Active Category ID')
    u_cat_csrf_token = HiddenField('csrf_token', validators=[DataRequired()])


class ItemForm(Form):
    c_item_name = StringField('Item', validators=[DataRequired()])
    c_item_description = TextAreaField('Description')
    c_item_category = SelectField('Category', validators=[DataRequired()])
    c_item_image = FileField('Image File')
    c_item_csrf_token = HiddenField('csrf_token', validators=[DataRequired()])


class DeleteItemForm(Form):
    d_item_csrf_token = HiddenField('csrf_token', validators=[DataRequired()])


# Definition of helper functions


UPLOAD_FOLDER = 'static/img/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def unique_filename():
    # We use mkstemp to create unique temporary files; as we are only
    # interested in the filename the files are remove after creation
    # Note: Alternatively, https://docs.python.org/3.5/library/uuid.html
    # could be used
    basename = "img_"
    fd, filepath = tempfile.mkstemp(
        prefix=basename, dir=app.config['UPLOAD_FOLDER'])
    os.close(fd)
    os.remove(filepath)
    return os.path.basename(filepath)


def initializeForms(categories):
    cform = CreateCategoryForm()
    dform = DeleteCategoryForm()
    uform = UpdateCategoryForm()
    ciform = ItemForm()
    ciform.c_item_category.choices = [("", "---")]
    for category in categories:
        ciform.c_item_category.choices.append((category.id, category.name))
    if 'state' in login_session:
        cform.c_cat_csrf_token.data = login_session['state']
        dform.d_cat_csrf_token.data = login_session['state']
        uform.u_cat_csrf_token.data = login_session['state']
        ciform.c_item_csrf_token.data = login_session['state']
    return cform, dform, uform, ciform


def initializeItemForm(categories):
    ciform = ItemForm()
    ciform.c_item_category.choices = [("", "---")]
    for category in categories:
        ciform.c_item_category.choices.append((category.id, category.name))
    diform = DeleteItemForm()
    if 'state' in login_session:
        ciform.c_item_csrf_token.data = login_session['state']
        diform.d_item_csrf_token.data = login_session['state']
    return ciform, diform


def latestItems():
    return session.query(Item).order_by(desc(Item.id)).limit(6).all()


def itemsOfCategory(categoryID):
    return session.query(Item).filter_by(category_id=categoryID).all()


# JSON Endpoints

@app.route('/catalog.json/')
def fullJSON():
    categories = session.query(Category).order_by(asc(Category.name)).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/items.json/')
def itemsJSON():
    searchterm = request.args.get('autocomplete-input', '')
    items = session.query(Item).filter(
        Item.name.ilike('%{}%'.format(searchterm))).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/<string:categoryname>/<string:itemname>.json')
def itemJSON(categoryname, itemname):
    searchterm = request.args.get('autocomplete-input', '')
    item = session.query(Item).join(Category).filter(
        Category.name == categoryname, Item.name == itemname).all()
    return jsonify(item=[i.serialize for i in item])


# Show all categories
@app.route('/')
@app.route('/categories/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name)).all()
    latest_items = latestItems()
    cform, dform, uform, ciform = initializeForms(categories)

    return render_template('view_category_latest_items.html',
                           categories=categories,
                           selectedCat=None,
                           latest_items=latest_items,
                           cform=cform,
                           dform=dform,
                           uform=uform,
                           ciform=ciform)


@app.route('/categories/<string:categoryname>/')
def showItems(categoryname):
    categories = session.query(Category).order_by(asc(Category.name)).all()
    # func.upper() used to make the URL case insensitive
    category = session.query(Category).filter(
        func.upper(Category.name) == func.upper(
            categoryname)).first()
    items = itemsOfCategory(category.id)
    cform, dform, uform, ciform = initializeForms(categories)
    return render_template('view_category_items.html',
                           categories=categories,
                           selectedCat=category,
                           items=items,
                           cform=cform,
                           dform=dform,
                           uform=uform,
                           ciform=ciform)


@app.route('/categories/<string:categoryname>/<string:itemname>')
def showItem(categoryname, itemname):
    # join() used to address the case when two different
    # categories contain an item with the same name
    item = session.query(Item).join(Category).filter(
        Category.name == categoryname, Item.name == itemname).first()
    categories = session.query(Category).order_by(asc(Category.name)).all()

    ciform, diform = initializeItemForm(categories)
    # Populate the fields of the edititem.html form with the
    #  respective values of the selected item
    if 'username' in login_session:
        ciform.c_item_category.default = item.category_id
        ciform.process()
        ciform.c_item_csrf_token.data = login_session['state']
        ciform.c_item_name.data = item.name
        ciform.c_item_description.data = item.description

    return render_template('item.html', item=item,
                           ciform=ciform, diform=diform)


@app.route('/categories/new/', methods=['POST'])
def newCategory():
    # User needs to be logged in for CRUD operations.
    # Redirect User to Login screen if he is not logged in
    if 'username' not in login_session:
        return redirect('/login')

    form = CreateCategoryForm(request.form)

    if form.validate():
        # Verify CSRF token
        if form.c_cat_csrf_token.data != login_session['state']:
            abort(403)
        else:
            newCategory = Category(
                name=form.c_cat_name.data, user_id=login_session['user_id'])
            session.add(newCategory)
            session.commit()
            categories = session.query(Category).order_by(
                asc(Category.name)).all()
            ciform, diform = initializeItemForm(categories)

            # Render HTML that needs to be updated (via AJAX)
            html = [render_template('categories.html',
                                    categories=categories,
                                    selectedCat=None),
                    render_template('addItem.html', ciform=ciform)]
            message = '<p>New category <b>{}</b> successfully created!</p>'
            return jsonify(data={
                'message': message.format(escape(form.c_cat_name.data)),
                'status': 1,
                'html': html
            })
    return jsonify(data=form.errors)


@app.route('/categories/delete/', methods=['POST'])
def deleteCategory():
    if 'username' not in login_session:
        return redirect('/login')

    dform = DeleteCategoryForm(request.form)
    if dform.validate():
        if dform.d_cat_csrf_token.data != login_session['state']:
            abort(403)

        category_id = dform.d_cat_id.data
        categoryToDelete = session.query(
            Category).filter_by(id=category_id).one()
        if login_session['user_id'] != categoryToDelete.user_id:
            abort(403)
        else:
            session.delete(categoryToDelete)
            session.commit()
            active_category_id = dform.d_active_cat_id.data
            if category_id == active_category_id:
                message = '<p>Category <b>{}</b> successfully deleted!</p>'
                flash(message.format(escape(categoryToDelete.name)))
                return jsonify(data={'redirect': url_for("showCategories")})
            else:
                categories = session.query(Category).order_by(
                    asc(Category.name)).all()
                if active_category_id:
                    selectedCategory = session.query(
                        Category).filter_by(id=active_category_id).one()
                else:
                    selectedCategory = None
                ciform, diform = initializeItemForm(categories)
                html = [render_template(
                    'categories.html',
                    categories=categories,
                    selectedCat=selectedCategory),
                    render_template('addItem.html', ciform=ciform)
                ]
                message = '<p>Category <b>{}</b> successfully deleted!</p>'
                return jsonify(data={
                    'message': message.format(escape(categoryToDelete.name)),
                    'status': 1,
                    'html': html
                })
    return jsonify(data=dform.errors)


@app.route('/categories/update/', methods=['POST'])
def updateCategory():
    if 'username' not in login_session:
        return redirect('/login')

    uform = UpdateCategoryForm(request.form)
    if uform.validate():
        if uform.u_cat_csrf_token.data != login_session['state']:
            abort(403)

        category_id = uform.u_cat_id.data
        categoryToUpdate = session.query(
            Category).filter_by(id=category_id).one()
        if login_session['user_id'] != categoryToUpdate.user_id:
            abort(403)
        else:
            categoryToUpdate.name = uform.u_cat_name.data
            session.add(categoryToUpdate)
            session.commit()
            active_category_id = uform.u_active_cat_id.data

            if category_id == active_category_id:
                message = '<p>Category <b>{}</b> successfully edited!</p>'
                flash(message.format(escape(categoryToUpdate.name)))
                return jsonify(data={
                    'redirect': url_for("showItems",
                                        categoryname=categoryToUpdate.name)
                })
            else:
                categories = session.query(Category).order_by(
                    asc(Category.name)).all()
                if active_category_id:
                    selectedCategory = session.query(
                        Category).filter_by(id=active_category_id).one()
                else:
                    selectedCategory = None
                ciform, diform = initializeItemForm(categories)
                html = [
                    render_template('categories.html',
                                    categories=categories,
                                    selectedCat=selectedCategory),
                    render_template('addItem.html',
                                    ciform=ciform)
                ]
                message = '<p>Category <b>{}</b> successfully edited!</p>'
                return jsonify(data={
                    'message': message.format(escape(categoryToUpdate.name)),
                    'status': 1,
                    'html': html
                })
    return jsonify(data=uform.errors)


@app.route('/item/new/', methods=['POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')

    form = ItemForm(request.form)
    # As "Choices" have not been set in the form class (for dynamic Choices),
    # we must add the Choices here so the form.validate() function below can
    # check if we made a valid choice
    form.c_item_category.choices = [("", "---")]
    categories = session.query(Category).order_by(asc(Category.name)).all()
    for category in categories:
        form.c_item_category.choices.append((str(category.id), category.name))

    if form.validate():
        if form.c_item_csrf_token.data != login_session['state']:
            abort(403)
        else:
            image = request.files['c_item_image']
            if image.filename == '':
                print("no file selected")
                newItem = Item(
                    name=form.c_item_name.data,
                    description=form.c_item_description.data,
                    category_id=int(request.form['c_item_category']),
                    user_id=login_session['user_id']
                )
            elif image and allowed_file(image.filename):
                originalFilename = secure_filename(image.filename)
                extension = os.path.splitext(originalFilename)[1]
                newfilename = unique_filename() + extension
                image.save(os.path.join(
                    app.config['UPLOAD_FOLDER'], newfilename))
                newItem = Item(
                    name=form.c_item_name.data,
                    description=form.c_item_description.data,
                    picture=newfilename,
                    category_id=int(request.form['c_item_category']),
                    user_id=login_session['user_id']
                )
            else:
                message = 'File type not allowed! Please try again.'
                return jsonify(data={'message': message, 'status': 0})
            session.add(newItem)
            session.commit()
            latest_items = latestItems()
            items = itemsOfCategory(int(request.form['c_item_category']))
            html = [
                render_template('latestItems.html',
                                latest_items=latest_items),
                render_template('items.html', items=items)
            ]
            message = '<p>New Item <b>{}</b> successfully created!</p>'
            return jsonify(data={
                'message': message.format(escape(form.c_item_name.data)),
                'status': 1,
                'html': html
            })
    return jsonify(data=form.errors)


@app.route('/<int:item_id>/edit/', methods=['POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    form = ItemForm(request.form)
    # As "Choices" have not been set in the form class (for dynamic Choices),
    # we must add the Choices here so the form.validate() function below can
    # check if we made a valid choice
    form.c_item_category.choices = [("", "---")]
    categories = session.query(Category).order_by(asc(Category.name)).all()
    for category in categories:
        form.c_item_category.choices.append((str(category.id), category.name))

    if form.validate():
        if form.c_item_csrf_token.data != login_session['state']:
            abort(403)

        itemToEdit = session.query(Item).filter_by(id=item_id).one()
        if login_session['user_id'] != itemToEdit.user_id:
            abort(403)
        else:
            itemToEdit.name = form.c_item_name.data
            itemToEdit.description = form.c_item_description.data
            itemToEdit.category_id = int(request.form['c_item_category'])
            image = request.files['c_item_image']

            if image.filename == '':
                print("no file selected")
            elif image and allowed_file(image.filename):
                if itemToEdit.picture:
                    # Remove previous image
                    oldfile = itemToEdit.picture
                    os.remove(os.path.join(
                        app.config['UPLOAD_FOLDER'], oldfile))
                # Rename new image and save it
                originalFilename = secure_filename(image.filename)
                extension = os.path.splitext(originalFilename)[1]
                newfilename = unique_filename() + extension
                image.save(os.path.join(
                    app.config['UPLOAD_FOLDER'], newfilename))
                # Change filename in database with the newly generated
                # filename of the new image
                itemToEdit.picture = newfilename
            else:
                return jsonify(data={
                    'message': 'File type not allowed! Please try again.',
                    'status': 0
                })
            session.add(itemToEdit)
            session.commit()

            message = '<p>Item <b>{}</b> successfully edited!</p>'
            flash(message.format(escape(itemToEdit.name)))
            return jsonify(data={
                'redirect': url_for("showItem",
                                    categoryname=itemToEdit.category.name,
                                    itemname=itemToEdit.name)
            })
    return jsonify(data=form.errors)


@app.route('/<int:item_id>/delete/', methods=['POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    form = DeleteItemForm(request.form)

    if form.validate():
        if form.d_item_csrf_token.data != login_session['state']:
            abort(403)

        itemToDelete = session.query(Item).filter_by(id=item_id).one()
        if login_session['user_id'] != itemToDelete.user_id:
            abort(403)
        else:
            session.delete(itemToDelete)
            redirectURL = url_for(
                "showItems", categoryname=itemToDelete.category.name)
            session.commit()

            # Remove image
            if itemToDelete.picture:
                file = itemToDelete.picture
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file))

            message = '<p>Item <b>{}</b> successfully deleted!</p>'
            flash(message.format(escape(itemToDelete.name)))
            return jsonify(data={'redirect': redirectURL})


@app.route('/images/<path:filename>')
def uploadedFile(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# OAUTH Hybrid Flow Login

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError, e:
        print(e)
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 402)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 404)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '''
    " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;">
    '''
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and
        select the first index which gives us the key : value for
        the server access token then we split it on colons to pull
        out the actual token value and replace the remaining quotes
        with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '''
    " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;">
    '''

    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
