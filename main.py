from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from uuid import uuid4
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from ldap3 import Server, Connection, ALL
from datetime import datetime, timedelta
from sqlalchemy import Integer, DateTime
from datetime import datetime, timedelta

def LDAP_AUTH(domain, username, password):
    didConnect = False
    try:
        # Define the server and connection settings
        server = Server(f"ldap://{domain}", get_info=ALL)
        conn = Connection(server, user=f"{username}@{domain}", password=password, auto_bind=True)
        # Attempt to bind (authenticate) the user
        conn.bind()
        # Check if the bind was successful
        if conn.result['result'] == 0:
            print("Authentication successful")
            didConnect = True
    except:
        print("Authentication failed")
    finally:
        # Don't forget to close the connection when you're done
        try:
            conn.unbind()
        except:
            ''
    return didConnect

app = FastAPI()
templates = Jinja2Templates(directory="./static")

# Mount the "/static" path to serve static files from the "static" directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create an in-memory SQLite database
engine = create_engine('sqlite:///:memory:', echo=True)

# Create a session factory
SessionLocal = sessionmaker(bind=engine)

# Create a base class for declarative models
Base = declarative_base()

# Define a Session model
class Session(Base):
    __tablename__ = 'session'
    id = Column(String(36), primary_key=True)
    username = Column(String, nullable=True)
    session_timeout = Column(DateTime, nullable=True)
    

# Create all tables in the database
Base.metadata.create_all(engine)

# Define a route for serving a simple login page and redirecting to /protected-web upon successful authentication

@app.route('/auth-web', methods=['GET', 'POST'])
async def auth_web(request: Request):
    error_message = None

    if request.method == 'POST':
        form = await request.form()
        username = form.get('username')
        password = form.get('password')

        if LDAP_AUTH("mycompany.com", username, password):
            # Update the expiration time (e.g., 30 minutes from now)
            expiration_time = datetime.now() + timedelta(minutes=30)

            # Generate a unique session ID
            session_id = str(uuid4())

            # Store the session information in the database with the correct username
            db = SessionLocal()
            session = Session(id=session_id, username=username, session_timeout=expiration_time)
            db.add(session)
            db.commit()
            db.close()
            print('added:', session_id, username, expiration_time)
            # Set cookies with session information
            response = RedirectResponse(url='/protected-web')
            response.set_cookie(key='session_id', value=session_id)
            response.set_cookie(key='message', value="mark's message")
            response.set_cookie(key='username', value=username)

            return response
        else:
            error_message = 'Invalid credentials'

    return templates.TemplateResponse("login.html", {"request": request, "error_message": error_message})

# Define a route for accessing protected content with HTML response
# Define a route for accessing protected content with HTML response
@app.get('/protected-web', response_class=HTMLResponse)
@app.post('/protected-web', response_class=HTMLResponse)
async def protected_web(request: Request):
    session_id = request.cookies.get('session_id')
    username = request.cookies.get('username')
    message = request.cookies.get('message')

    # Check if both session_id and username are present in cookies
    if session_id and username:
        db = SessionLocal()
        # Query the database to find the user with the given username and session ID
        session = db.query(Session).filter(
            Session.id == session_id,
            Session.username == username,
            Session.session_timeout > datetime.now(),  # Check if the session has not expired
        ).order_by(Session.session_timeout.desc()).first()
        db.close()

        if session:
            return HTMLResponse(content=f"<h1>Hello user {username}!</h1> , {message}")
        else:
            print("Authentication failed for session_id:", session_id)
            raise HTTPException(status_code=401, detail='Unauthorized')
    else:
        print("Session ID or username not present in cookies.")
        raise HTTPException(status_code=401, detail='Unauthorized')
