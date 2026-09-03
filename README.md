# Attack-Surface-Mapping
Analyzed Calibre-Web NextGen’s application structure to identify security-sensitive components, entry points, user inputs, authentication paths, file operations, and trust boundaries.  Outcome: Created an attack surface map to guide deeper vulnerability analysis and testing.

Start from PowerShell and make sure you're inside the target: cd C:\Users\eelve\Vulnerability-Research-Lab\targets\Calibre-Web-NextGen

Your prompt should look similar to: (.venv) PS C:\Users\eelve\Vulnerability-Research-Lab\targets\Calibre-Web-NextGen>

Now run: Get-ChildItem

This removes the individual files and lets us concentrate on the major directories.

Identify important project files run: Get-ChildItem -File
We're looking for things such as:

README files

requirements files

pyproject.toml

Dockerfile

docker-compose files

configuration files

package files

security documentation

Confirm our baseline hasn't changed Run: git status

We still want:

On branch main

nothing to commit, working tree clean

This is important because we're beginning analysis from the exact baseline recorded in Lab 2.

At this stage, don't think "Where is the vulnerability?"

Instead think "Where does untrusted information enter the application, what happens to it, and what security boundary does it cross?"

For example, an upload feature isn't automatically vulnerable. It's an attack surface because untrusted data enters the application there.

Similarly:

Login page → attack surface

Search box → attack surface

API endpoint → attack surface

File upload → attack surface

Administrative functionality → high-value attack surface

That's the mindset I want you developing before we touch Semgrep or CodeQL.

Stop after these commands

Run:

Get-ChildItem

Get-ChildItem -Directory

Get-ChildItem -File

git status

**Identify the Application Architecture**

inspect cps first because it appears to be the primary application directory. Run: Get-ChildItem .\cps

Then let's identify the Python source files. run: Get-ChildItem .\cps -Filter *.py

Next, look at the application's Python configuration. Run: Get-Content .\pyproject.toml

And check the application's recorded version. Run: Get-Content .\VERSION

**Find the Security-Sensitive Components**

Now let's start mapping what the Python application actually does.

Run this first: Get-ChildItem .\cps -Filter *.py | Select-Object Name

We're looking for filenames related to things like:

authentication → authorization → uploads → APIs → admin functions → database → file handling

Then run: Select-String -Path .\cps\*.py -Pattern "@.*route" | Select-Object Path, LineNumber, Line

This searches the source code for web route definitions.

**Map Authentication and Authorization**

Before we test any endpoint, we need to answer:

What prevents an unauthorized user from reaching these functions?

Run this first: Select-String -Path .\cps\*.py -Pattern "login_required|admin_required|current_user" | Select-Object Path, LineNumber, Line

Then check CSRF-related code: Select-String -Path .\cps\*.py -Pattern "csrf|CSRF" | Select-Object Path, LineNumber, Line

Next, let's inspect the login code itself: Get-Content .\cps\web.py | Select-Object -Skip 2900 -First 140

And the upload route. Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 90 -First 100

What we're looking for

We're not trying to exploit anything yet. We're identifying whether sensitive routes have protections such as:

Authentication required

        ↓
        
Authorization / role check

        ↓
        
CSRF protection

        ↓
        
Input validation

        ↓
        
Sensitive action

For the upload path we'll later map:

User-controlled file

        ↓
        
Upload endpoint

        ↓
        
Filename validation

        ↓
File-type validation

        ↓
        
Storage location

        ↓
        
Book processing

That could eventually become an important research area, but an upload feature is not a vulnerability by itself.

**understand the authorization decorators**

From your current directory, run: Select-String -Path .\cps\*.py -Pattern "def upload_required|def edit_required|def admin_required" | Select-Object Path, LineNumber, Line


Then run: Get-Content .\cps\usermanagement.py | Select-Object -Skip 240 -First 90

And: Get-Content .\cps\admin.py | Select-Object -Skip 105 -First 50

We're specifically trying to determine whether the authorization chain really behaves like:

HTTP Request

     ↓
     
Authentication

     ↓
     
User identity

     ↓
     
Role / permission check

     ↓ 
     
Route handler

     ↓
     
Sensitive operation

The admin_required decorator is straightforward: it checks current_user.role_admin() and returns HTTP 403 when the user is not an administrator. So administrative endpoints do have an explicit privilege boundary.

The more interesting behavior is login_required_if_no_ano:

if config.config_anonbrowse == 1:

    return func(*args, **kwargs)

That means when anonymous browsing is enabled, this decorator alone does not require authentication. That is not automatically a vulnerability because sensitive endpoints can—and should—have an additional permission decorator. Your /upload route does:

@login_required_if_no_ano

@upload_required

So now the critical question is: Does upload_required correctly reject an anonymous/Guest user?

**Inspect Role Enforcement**

Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 40 -First 45

This should show both:

upload_required

We also discovered another important attack surface: reverse-proxy authentication.

The application can trust a configured HTTP header and use its value to identify an existing user:

HTTP Request

    ↓
    
Configured reverse-proxy header

    ↓
    
Username extracted

    ↓
    
Existing account lookup

    ↓
    
User authenticated

That makes the reverse-proxy boundary security-sensitive. Again, we have not found a vulnerability; this is exactly what attack-surface mapping is supposed to uncover.

Let's inspect the rest of that function too. Run: Get-Content .\cps\usermanagement.py | Select-Object -Skip 284 -First 115

Your attack-surface map is now developing into this

What we confirmed

The upload endpoint has a meaningful second authorization layer:

if current_user.role_upload() and uploads_enabled(config):

    return f(*args, **kwargs)
    
abort(403)

So reaching /upload requires the current user to have the upload role and for uploads to be enabled. Likewise, edit_required permits the operation only when the user has the edit role or administrator role.

That means we currently have no evidence of an upload authorization bypass. We document the control and keep moving.

The reverse-proxy authentication path is more security-sensitive. When that feature is enabled, the application obtains a username from a configured request header, searches for the corresponding account, and can treat that identity as authenticated. It can also automatically create an account when the appropriate configuration option is enabled.

Again, that's not a vulnerability. It tells us there is an important trust boundary:

Client request

      ↓
      
Reverse proxy

      ↓
      
Authentication header

      ↓
      
Calibre-Web NextGen

      ↓
      
Account lookup / creation

      ↓
      
Authenticated identity

The security of that design depends heavily on the deployment ensuring that an untrusted client cannot directly supply a trusted authentication header.

**Map File Upload Processing**

We now understand who is supposed to be allowed to upload. Next we need to understand what happens to an uploaded file.

Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 100 -First 220

Then search for filename handling. Run: Select-String -Path .\cps\editbooks.py -Pattern "secure_filename|filename|extension|mimetype" | Select-Object LineNumber, Line

And search for where uploaded files are written . Run: Select-String -Path .\cps\editbooks.py -Pattern "\.save\(|write\(|copy\(|move\(" | Select-Object LineNumber, Line

What we're mapping

Uploaded file

     ↓
     
Filename

     ↓
     
Extension/type validation

     ↓
     
Filename sanitization

     ↓
     
Destination path

     ↓
     
File write

     ↓
     
Book/metadata processing

Pay particular attention to the fact that secure_filename is imported. Its presence alone doesn't prove uploads are safe—we need to determine where and how it's actually used.

The key write path in the upload flow appears at line 532:

uploaded_file.save(tmp_path)

That means the staged upload is written to a temporary path first, which matches the ingest workflow we already mapped. You also found a separate direct save at line 2344:

requested_file.save(saved_filename)

That second path is worth tracking separately because it may represent a different upload or replacement workflow than the primary ingest path.

**Inspect the exact write logic**

Run:Get-Content .\cps\editbooks.py | Select-Object -Skip 500 -First 80

This should show the function around: uploaded_file.save(tmp_path)

Then run: Get-Content .\cps\editbooks.py | Select-Object -Skip 2280 -First 90

This should show the separate code path around: requested_file.save(saved_filename)

We want to answer one specific question:

User filename

    ↓
    
Sanitization

    ↓
    
Path construction

    ↓
    
Temporary or final destination

    ↓
    
File write

If the first path uses a generated or sanitized filename and writes only into the controlled ingest directory, that is a strong design control.

The second path deserves its own entry in the attack-surface map because a direct save(saved_filename) may have different path-building and authorization rules.

The first upload path saves to a temporary .uploading file inside the ingest directory, cleans up partial files on failure, and only later gets renamed into place. That gives us a controlled staging boundary instead of writing directly into the library.

The second path is also important because requested_file.save(saved_filename) writes directly into the Calibre library, but the final filename is not taken directly from the uploaded filename. It is built from the existing book.path, the existing book name, and the validated file extension:

book.path

   ↓
   
normalized library path

   ↓
   
existing book filename

   +
   
validated extension

   ↓
   
saved_filename

Before that save, the code checks the configured allowed extensions, optionally performs MIME validation, and verifies that the current user has the upload role. So at this stage, we do not have evidence of arbitrary path control or an unrestricted upload vulnerability

Add this to your Lab 3 attack-surface notes

The main data flow we've mapped is now:

Authenticated/authorized user

        ↓
        
Uploaded file

        ↓
        
Extension/MIME validation

        ↓
        
Filename/path handling

        ↓
Temporary ingest staging

        ↓
        
Sidecar manifest

        ↓
        
Atomic rename

        ↓
        
Backend ingest processing

        ↓
        
Calibre library

**Next Surface: Remote Login / Token Handling**

Run: Get-Content .\cps\remotelogin.py | Select-Object -First 170

Then run: Select-String -Path .\cps\remotelogin.py -Pattern "token|random|verify|expire|delete|user_id" | Select-Object LineNumber, Line

Here we're trying to understand:

Remote login request

      ↓
      
Token creation

      ↓
      
Token storage

      ↓
      
Token verification

      ↓
      
User association

      ↓
      
Authenticated session

We are still mapping only. We are not trying to bypass authentication yet.

The process appears to be:

Unauthenticated device

        ↓
        
GET /remote/login

        ↓
        
RemoteAuthToken created

        ↓
        
Verification URL / QR code generated

        ↓
        
Authenticated user opens /verify/<token>

        ↓
        
@user_login_required

        ↓
        
Token existence + expiration checked

        ↓
        
Token assigned current_user.id

        ↓
        
verified = True

        ↓
        
Original device POSTs token to /ajax/verify_token

        ↓
        
Token existence + expiration + verified checked

        ↓
        
Associated user loaded

        ↓
        
login_user(user)

        ↓
        
Token deleted

        ↓
        
Authenticated session

There are several security controls already visible. /verify/<token> requires an authenticated user because of @user_login_required. Both verification paths check whether the token exists and whether it has expired. The polling endpoint also requires verified == True, and after successful authentication the token is deleted, giving it one-time-use behavior.

Important attack surface

The token itself is effectively an authentication credential during this workflow. Anyone possessing the correct token potentially controls which browser receives the resulting authenticated session once an authenticated user verifies it.

That does not mean we found a vulnerability. Before making any security conclusion, we need to answer two important questions:

How is RemoteAuthToken.auth_token generated, and how long is it valid?

Those properties determine whether the token has sufficient entropy and an appropriate lifetime.

**Inspect RemoteAuthToken**

Run: Select-String -Path .\cps\ub.py -Pattern "class RemoteAuthToken" | Select-Object LineNumber, Line

Then: Select-String -Path .\cps\ub.py -Pattern "auth_token|expiration|RemoteAuthToken" | Select-Object LineNumber, Line

Once you know the class's line number, we'll display the actual class. For example, if PowerShell says it starts around line 900, we'd use:
Get-Content .\cps\ub.py | Select-Object -Skip 890 -First 70

Don't use 890 yet—use the line number your first command gives us.

We're specifically looking for:

Token generation method

Token length / entropy

Expiration period

Default verified state

Default user association

Database uniqueness

Your output shows that RemoteAuthToken is defined at line 2197, with:

auth_token = Column(String, unique=True)

expiration = Column(DateTime)

and the token is generated with:

self.auth_token = (hexlify(os.urandom(16))).decode('utf-8')

self.expiration = datetime.now() + timedelta(minutes=10)

That means the remote-login token uses 16 random bytes, which becomes a 32-character hexadecimal token. That is about 128 bits of randomness, which is strong enough that brute-forcing the token is not a realistic attack path under normal conditions. The token also expires after 10 minutes, which further limits exposure.

Our current assessment is:

We are going to make one correction since the last Get-Content command used -Skip 890, so it displayed the wrong part of ub.py. Since the class starts at line 2197, run this instead:

Get-Content .\cps\ub.py | Select-Object -Skip 2190 -First 45

That will let us see the entire RemoteAuthToken class, including default values such as verified, user_id, and any token_type behavior.

What we confirmed
class RemoteAuthToken(Base):
    __tablename__ = 'remote_auth_token'

    id = Column(Integer, primary_key=True)
    auth_token = Column(String, unique=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    verified = Column(Boolean, default=False)
    expiration = Column(DateTime)
    token_type = Column(Integer, default=0)

The security-relevant lifecycle is now clear:

Token created

    ↓
    
os.urandom(16)

    ↓
    
128-bit random token

    ↓
    
verified = False
user_id = unset

expiration = now + 10 minutes

    ↓
    
Authenticated user verifies token

    ↓
    
user_id = current_user.id
verified = True

    ↓
    
Requesting device presents token

    ↓
    
Existence / expiration / verified checks

    ↓
    
login_user(user)

    ↓
    
Token deleted

There is one additional field, token_type, that we haven't fully traced. We saw earlier that expired-token cleanup treats some token types differently, so it's worth documenting later, but there's no reason to stay stuck on this component during attack-surface mapping.

Remote-login attack surface: mapped. No vulnerability identified at this stage.

**Object-Level Authorization**

Now we'll map whether operations involving a book_id verify that the current user should actually be able to operate on that particular book.

Start with:

Select-String -Path .\cps\*.py -Pattern "book_id.*current_user|current_user.*book_id" | Select-Object Path, LineNumber, Line

Then: Select-String -Path .\cps\editbooks.py -Pattern "get_book\(book_id\)|filter.*book_id|book_id ==" | Select-Object LineNumber, Line

We're looking for the distinction between:

User has EDIT permission

        ↓
        
Can edit books

and:

User has EDIT permission

        ↓
        
Requests book_id = X

        ↓
        
Is user authorized for this particular book?

        ↓
        
Allow / deny

This is important because role-based authorization and object-level authorization are different security boundaries. We are still mapping the implementation—not attempting an IDOR/BOLA test yet.

The key point is that this broad search returns many matches, but most are not automatically authorization checks. Some are logging, reading-state tracking, favorites, annotations, shelves, and other user-specific operations. We should narrow it instead of assuming any match represents a vulnerability.

One particularly interesting function is:

cover_preview_blueprint.py

_resolve_book_for_current_user(...)

The name strongly suggests the project already has explicit object-level access-control logic in at least part of the application. That gives us something useful to compare against other book endpoints.

**Inspect Book Object Authorization**

First, inspect that resolver: Get-Content .\cps\cover_preview_blueprint.py | Select-Object -Skip 325 -First 55

Then inspect the main book-editing flow around the match at line 1003: Get-Content .\cps\editbooks.py | Select-Object -Skip 980 -First 90

Finally, your search results show a large concentration of user/book logic near the beginning of web.py. Let's inspect that region:
Get-Content .\cps\web.py | Select-Object -Skip 300 -First 180

We're comparing three things:

Book ID supplied

      ↓
      
Book exists?

      ↓
      
Does current user have access to this book?

      ↓
      
Does current user have permission for this operation?

      ↓
      
Operation allowed

Don't test or manipulate IDs yet. We're still doing static attack-surface mapping.

Once we see those three outputs, we'll determine whether Calibre-Web NextGen uses a consistent centralized object-access mechanism or whether authorization varies between endpoints. That will tell us whether object-level authorization deserves deeper attention when we eventually enter the vulnerability-testing labs.

These outputs give us useful evidence about how Calibre-Web NextGen handles object-level authorization and visibility.

What we confirmed

The strongest finding is that the application has a centralized book-filtering mechanism:

return calibre_db.get_filtered_book(book_id, allow_show_archived=True)

The source comments explicitly say this applies visibility restrictions including anonymous mode, hidden books, archived state, and role restrictions, returning None when the caller cannot see the book.

More importantly, the primary book-editing function also uses that filtered lookup:

book = calibre_db.get_filtered_book(
    book_id,
    
    allow_show_archived=True,
    
    allow_show_hidden=True
    
)

and rejects inaccessible/nonexistent books before proceeding.

Combined with the route-level @edit_required control we examined earlier, the editing path therefore appears to have two layers:

User requests book_id

        ↓
        
Authentication

        ↓
        
EDIT/ADMIN role authorization

        ↓
        
get_filtered_book(book_id)

        ↓
        
Book visibility/access filtering

        ↓
        
Book exists and is accessible?

      ↙       ↘
      
    No         Yes
    
     ↓          ↓
     
 Reject      Continue

That's good security architecture. We currently have no evidence of an IDOR/BOLA in the main edit-book path.

But there is something worth mapping

Your web.py output shows several endpoints accepting a user-controlled book_id, including:

/ajax/toggleread/<book_id>

/ajax/togglearchived/<book_id>

/ajax/togglefavorite/<book_id>

/ajax/mylibrary/<book_id>/add

/ajax/mylibrary/<book_id>/remove

/ajax/togglehidden/<book_id>

Some clearly bind database changes to current_user.id. For example, favorites query both the current user's ID and supplied book ID. Hidden-book state similarly associates the operation with the authenticated user.

However, binding a record to the current user isn't necessarily the same thing as checking whether that user may access the supplied book.

We don't call this a vulnerability. It simply gives us a good mapping question for the underlying helper functions.

**Trace the authorization helpers**

Let's inspect the two functions called by these endpoints. Run: Select-String -Path .\cps\*.py -Pattern "def edit_book_read_status|def change_archived_books" |
Select-Object Path, LineNumber, Line

And: Select-String -Path .\cps\user_library.py -Pattern "def add_book|def remove_book|def removal_impact" | Select-Object LineNumber, Line

At this point we've mapped four major areas:

Authentication → Upload authorization → File/ingest processing → Remote-login tokens → Book/object authorization

The objective remains to identify where deeper testing should happen in later labs, not to force a vulnerability finding during attack-surface mapping.

