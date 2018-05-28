from flask import (Flask,
                   render_template,
                   redirect,
                   url_for,
                   request,
                   flash,
                   jsonify,
                   make_response,
                   session as login_session)
import random
import string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
app = Flask(__name__)
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)


@app.route('/login')
def showLogin():
    '''log in by third-party oauth'''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template("login.html", STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''log in by google account'''
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
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
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
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
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

    # check if user exists in database
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # format the output
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    '''log out from google account'''
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    '''log out from third-party oauth'''
    # check the provider of the third-party oauth
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']

    # delete user info
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash('You have successfully been logged out')
        return redirect(url_for('showCategories'))
    else:
        flash('You were not logged in to begin with!')
        redirect(url_for('showCategories'))


# user helper functions
def createUser(login_session):
    session = DBSession()
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
@app.route('/catalog/')
def showCategories():
    '''show all categories in the catalog'''
    session = DBSession()
    categories = session.query(Category).all()

    # check if user is logged in
    if 'user_id' not in login_session:
        return render_template(
            'publiccategories.html',
            categories=categories,
            log_in=False
            )
    else:
        return render_template(
            'categories.html',
            categories=categories,
            log_in=True
            )


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    '''add a new category into the catalog'''
    # check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()

    # create a new category
    if request.method == 'POST':
        print('Login_Session ID:', login_session['user_id'])
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('New Category created!')
        return redirect(url_for('showCategories'))
    else:
        return render_template('newcategory.html')


@app.route('/catalog/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    '''edit the existing category in the catalog'''
    # check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()
    editedCategory = session.query(Category).filter_by(
        id=category_id).one()
    creator = getUserInfo(editedCategory.user_id)

    # check if current user if the creator
    if creator.id != login_session['user_id']:
        flash('You are not authorized to edit others.')
        return redirect(url_for('showCategories'))

    # edit the existing category
    if request.method == 'POST':
    	if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash('Category edited!')
        return redirect(url_for('showCategories'))
    else:
        return render_template(
            'editcategory.html',
            category_id=category_id,
            category=editedCategory)


@app.route('/catalog/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    '''delete a category from the catalog'''
    # check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()
    deleteCategory = session.query(Category).filter_by(
        id=category_id).one()
    creator = getUserInfo(deleteCategory.user_id)

    # check if current user is the creator
    if creator.id != login_session['user_id']:
        flash('You are not authorized to delete others.')
        return redirect(url_for('showCategories'))

    # delete the category
    if request.method == 'POST':
        session.delete(deleteCategory)
        session.commit()
        flash('Category deleted!')
        return redirect(url_for('showCategories'))
    else:
        return render_template(
            'deletecategory.html',
            category_id=category_id,
            category=deleteCategory)


@app.route('/catalog/<int:category_id>/')
@app.route('/catalog/<int:category_id>/item/')
def showCategoryItems(category_id):
    '''show all items in the specific category'''
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CategoryItem).filter_by(category_id=category_id)
    print("Creator ID:", category.user_id)
    creator = getUserInfo(category.user_id)

    # check if user is logged in
    if 'user_id' not in login_session or \
            login_session['user_id'] != creator.id:
        return render_template(
            'publiccategoryitems.html',
            items=items,
            category=category,
            creator=creator,
            log_in=False)
    else:
        return render_template(
            'categoryitems.html',
            category=category,
            category_id=category_id,
            items=items,
            creator=creator,
            log_in=True)


@app.route('/catalog/<int:category_id>/item/new/',
           methods=['GET', 'POST'])
def newCategoryItem(category_id):
    '''add a new item to the category'''
    # check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)

    # check if current user is the creator of the category
    if creator.id != login_session['user_id']:
        flash('You are not authorized to add items')
        return redirect(url_for('showCategoryItems', category_id=category_id))

    # create a new item
    if request.method == 'POST':
        newItem = CategoryItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_id=category.user_id)
        session.add(newItem)
        session.commit()
        flash('New menu item created!')
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('newcategoryitem.html', category_id=category_id)


@app.route('/catalog/<int:category_id>/item/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editCategoryItem(category_id, item_id):
    '''edit an existing item in the category'''
    # check if a user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()
    editedItem = session.query(CategoryItem).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)

    # check if current user is the creator of the category
    if creator.id != login_session['user_id']:
        flash('You are not authorized to edit items')
        return redirect(url_for('showCategoryItems', category_id=category_id))

    # edit an item
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Category item edited!')
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template(
            'editcategoryitem.html',
            category_id=category_id,
            item_id=item_id,
            item=editedItem)


@app.route('/catalog/<int:category_id>/item/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteCategoryItem(category_id, item_id):
    '''delete a item from the category'''
    # check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    session = DBSession()
    deleteItem = session.query(CategoryItem).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)

    # check if current user is the creator of the category
    if creator.id != login_session['user_id']:
        flash('You are not authorized to add items')
        return redirect(url_for('showCategoryItems', category_id=category_id))

    # delete the item
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash('Cateogry item deleted!')
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template(
            'deletecategoryitem.html',
            category_id=category_id,
            item_id=item_id, item=deleteItem)


@app.route('/catalog/JSON/')
def categoriesJSON():
    '''show JSON file of all categories'''
    session = DBSession()
    categorys = session.query(Category)
    return jsonify(Category=[r.serialize for r in categorys])


@app.route('/catalog/<int:category_id>/item/JSON/')
def categoryItemsJSON(category_id):
    '''show JSON file of all items in the category'''
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CategoryItem).filter_by(
        category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/catalog/<int:category_id>/item/<int:item_id>/JSON/')
def categoryItemJSON(category_id, item_id):
    '''show JSON file of the item'''
    session = DBSession()
    item = session.query(CategoryItem).filter_by(id=item_id).one()
    return jsonify(CategoryItems=item.serialize)

if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
