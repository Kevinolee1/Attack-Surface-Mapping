# Attack-Surface-Mapping
Analyzed Calibre-Web NextGen’s application structure to identify security-sensitive components, entry points, user inputs, authentication paths, file operations, and trust boundaries.  Outcome: Created an attack surface map to guide deeper vulnerability analysis and testing.

Start from PowerShell and make sure you're inside the target: cd C:\Users\eelve\Vulnerability-Research-Lab\targets\Calibre-Web-NextGen

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/c55d00a5d37e9e0c39964cf330918fb73a4833d7/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20104951.png)

Your prompt should look similar to: (.venv) PS C:\Users\eelve\Vulnerability-Research-Lab\targets\Calibre-Web-NextGen>

Now run: Get-ChildItem
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/82a5c813bea72585e270e6356a314e0da08f1cc0/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20105156.png)

This removes the individual files and lets us concentrate on the major directories.

Identify important project files run: Get-ChildItem -File

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/4f3da4ee7d616f3e0400a9374c51e528c6093cf5/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20105354.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/6818f5fa31df0143cfa97c6b38d5ef496a4ae981/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20105628.png)

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
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/4cd13057f5fcc6c54d0224162693cc47aa9739ad/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20110405.png)
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/0eebcd37216a76330687474f10f5dd56c6cc4797/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20110418.png)
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/c4d8e4e26aa6b7df28a9495f8e0bbd8ec0346778/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20110430.png)
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/e3f73fb7c0e71bd127d1090f0bbcea60fe284082/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20110446.png)


**Identify the Application Architecture**

inspect cps first because it appears to be the primary application directory. Run: Get-ChildItem .\cps

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/a528089bdd878cbb81d83b19b0a36056e5b0944b/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20145246.png)

Then let's identify the Python source files. run: Get-ChildItem .\cps -Filter *.py

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/49969aedad56636aae84c1c2a6b2e2bc8fc2100e/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20145246.png)

Next, look at the application's Python configuration. Run: Get-Content .\pyproject.toml

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/0eab0f6d01518f8a2d1be82868c1f4f9b3cbaba0/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20145535.png)

And check the application's recorded version. Run: Get-Content .\VERSION

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/56ef1cdb43fd034dbadef169efe974b5e9c74734/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20145704.png)

**Find the Security-Sensitive Components**

Now let's start mapping what the Python application actually does.

Run this first: Get-ChildItem .\cps -Filter *.py | Select-Object Name

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/b41677d680f5eb33e28063006d3d4df79c770ac3/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20150012.png)

We're looking for filenames related to things like:

authentication → authorization → uploads → APIs → admin functions → database → file handling

Then run: Select-String -Path .\cps\*.py -Pattern "@.*route" | Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/93b4becc6891c89c87323308beeef3cf4d08ef77/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20150514.png)

This searches the source code for web route definitions.

**Map Authentication and Authorization**

Before we test any endpoint, we need to answer:

What prevents an unauthorized user from reaching these functions?

Run this first: Select-String -Path .\cps\*.py -Pattern "login_required|admin_required|current_user" | Select-Object Path, LineNumber, Line

Then check CSRF-related code: Select-String -Path .\cps\*.py -Pattern "csrf|CSRF" | Select-Object Path, LineNumber, Line

Next, let's inspect the login code itself: Get-Content .\cps\web.py | Select-Object -Skip 2900 -First 140

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/2bd12c5c1d101310d95000d8efe5920c9c892a88/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20150741.png)

And the upload route. Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 90 -First 100

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/46461f7a7ef17b221d3f1ab4bdf6ffb0b1c98c52/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20150902.png)

What we're looking for

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/3513791d590720082ac6d8a6809ae1e164c4cb4c/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20200554.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/f4b5724a89be89cac01544b1423e882cb5ab5a58/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20194927.png)

Then run: Get-Content .\cps\usermanagement.py | Select-Object -Skip 240 -First 90

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/9622050a056986975a96e956fda6b8db75c306d7/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20195125.png)

And: Get-Content .\cps\admin.py | Select-Object -Skip 105 -First 50


![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/ad1aea47179cb8cbd721821649b684f89a090b8e/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20195357.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/3a971829b294f6db149679aa05edf8c8be96ebbf/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20195942.png)

This should show both:

upload_required

edit_required

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/5769e64dd76c9ba1199aff2c257b2866499d193c/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20200306.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/c03f365f3b856cf5d8cd693ca235247995f14c78/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20201625.png)

Then search for filename handling. Run: Select-String -Path .\cps\editbooks.py -Pattern "secure_filename|filename|extension|mimetype" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/2916aaca220557dcdf72638d9ba358d893a2c0b8/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20201918.png)

And search for where uploaded files are written . Run: Select-String -Path .\cps\editbooks.py -Pattern "\.save\(|write\(|copy\(|move\(" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/e7e93b33f51134077d74af3fb0ceafce226145c7/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20202012.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/cf4b9b7551ed6725d79cc4ae80c5ba0805031620/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20202635.png)

This should show the function around: uploaded_file.save(tmp_path)

Then run: Get-Content .\cps\editbooks.py | Select-Object -Skip 2280 -First 90

![image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/a247935eebc750624ea4df525350b0dba2764233/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20202747.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/213aa5fec66f918542388a396cdf0e6a7e05a655/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20203829.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/6bf949329890519bcef91f7b2634b3f16cd07840/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20204111.png)

Then run: Select-String -Path .\cps\remotelogin.py -Pattern "token|random|verify|expire|delete|user_id" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/52d6a7bf03e83214cb7a36e58e8d3d00e107a0a3/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20204228.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/823515ea7ee61c032b09b8d5ce388151b3b15862/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20205532.png)

Then: Select-String -Path .\cps\ub.py -Pattern "auth_token|expiration|RemoteAuthToken" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/2ac091ad0a2204e42af338fe075512473dd21422/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20205640.png)

Once you know the class's line number, we'll display the actual class. For example, if PowerShell says it starts around line 900, we'd use:
Get-Content .\cps\ub.py | Select-Object -Skip 890 -First 70

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/e8aa17e88ad5dcd8fbb4954a14e3daf725871b3b/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20205746.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/f3b59735209d166e805994e3c1dbf6c669d69f19/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20210229.png)

We are going to make one correction since the last Get-Content command used -Skip 890, so it displayed the wrong part of ub.py. Since the class starts at line 2197, run this instead:

Get-Content .\cps\ub.py | Select-Object -Skip 2190 -First 45

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/d5b4c2a2f4908b19c690066efe89112b20b2f9bb/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20210446.png)

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

Remote Logic ID assessment:

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/20ae8db09b164096b05dfb554e030426b9a5b785/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20210936.png)

There is one additional field, token_type, that we haven't fully traced. We saw earlier that expired-token cleanup treats some token types differently, so it's worth documenting later, but there's no reason to stay stuck on this component during attack-surface mapping.

Remote-login attack surface: mapped. No vulnerability identified at this stage.

**Object-Level Authorization**

Now we'll map whether operations involving a book_id verify that the current user should actually be able to operate on that particular book.

Start with:

Select-String -Path .\cps\*.py -Pattern "book_id.*current_user|current_user.*book_id" | Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/981bb88c7754d66308c5768db6466dbf768c82ed/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20211941.png)

Then: Select-String -Path .\cps\editbooks.py -Pattern "get_book\(book_id\)|filter.*book_id|book_id ==" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/9bb7339ee3773343336155f06ae0646a4171bc07/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20214529.png)

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

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/33a36a543111d070c9211c70aa55a2ba4e2a317a/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20213232.png)

Then inspect the main book-editing flow around the match at line 1003: Get-Content .\cps\editbooks.py | Select-Object -Skip 980 -First 90

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/17fd94eee783a741a0d262c03b321c139b44b540/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20213409.png)

Finally, your search results show a large concentration of user/book logic near the beginning of web.py. Let's inspect that region:
Get-Content .\cps\web.py | Select-Object -Skip 300 -First 180

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/55436629e8edc1073aac2319c24be0546c081227/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20213514.png)

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

Let's inspect the two functions called by these endpoints. 

Run: Select-String -Path .\cps\*.py -Pattern "def edit_book_read_status|def change_archived_books" |
Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/9b97c45abc94222449887604d5783aa18037db65/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20214437.png)

And: Select-String -Path .\cps\user_library.py -Pattern "def add_book|def remove_book|def removal_impact" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/33f6e96c2ebe0d434de7da27b7e0c118b00867f6/Attack%20Surface%20Mapping/Screenshot%202026-09-02%20214529.png)

At this point we've mapped four major areas:

Authentication → Upload authorization → File/ingest processing → Remote-login tokens → Book/object authorization

The objective remains to identify where deeper testing should happen in later labs, not to force a vulnerability finding during attack-surface mapping.

Run: Select-String -Path .\cps\*.py -Pattern "def edit_book_read_status|def change_archived_books" | Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/a149f6cddaadf54eb039832f11fa888182450ea5/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20204853.png)

Then: Select-String -Path .\cps\user_library.py -Pattern "def add_book|def remove_book|def removal_impact" |
Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/8d424a38a6e923a18d6874f9f6ebb9ecca87fb2c/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20204916.png)

We’re checking whether these helper functions enforce book-level access control, not just whether the user is logged in. After that, we’ll inspect the exact helper code and decide whether object-level authorization deserves deeper testing later.

We found all five functions. Now we can inspecting only the relevant sections.

Run: Get-Content .\cps\helper.py | Select-Object -Skip 900 -First 75

Next: Get-Content .\cps\kobo_sync_status.py | Select-Object -Skip 460 -First 55

Then: Get-Content .\cps\user_library.py | Select-Object -Skip 480 -First 145

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/6ea1b87798306a930b2ce0e7ad146d89e286bd7c/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20205142.png)

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/17a8d33c729b81a77644b26f87e9324dd3734e1f/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20205922.png)

we're checking

For each function, we're looking for this authorization chain:

User-controlled book_id

        ↓
        
Book lookup

        ↓
        
Current-user association
        ↓
        
Book visibility/access check

        ↓
        
Operation permitted

Specifically:

We found 

edit_book_read_status() → can the user modify only appropriate reading-state records?
change_archived_books() → is archive state properly tied to the current user?
add_book() → does it validate the requested book?
remove_book() → does it operate only on the user's library?
removal_impact() → does it expose information only about books the user should access?

For edit_book_read_status(), the default branch binds the state change to current_user.id, which prevents one user from directly modifying another user's read-status row. However, in that branch I do not see a call to calibre_db.get_filtered_book() before creating or updating the ReadBook record. The custom-column branch does use get_filtered_book(book_id, True). That inconsistency is worth documenting, but it is not yet a vulnerability.

Fhange_archived_books() also binds the archive record to current_user.id, but the code you pasted does not show a book visibility/access check before creating or updating the ArchivedBook row.

This does not mean IDOR/BOLA is confirmed. It means we found inconsistent object-validation patterns that should become a priority in a later validation lab.

That completes the code review we needed

What the user_library.py review shows

add_book() has a strong object-level control. Before adding a book, _add_visible_book() checks the requested book_id against common_filters() for that specific user. If the book isn't visible to that user, the operation raises UserLibraryBookNotFound.

remove_book() is also strongly user-bound. Its deletion requires both:

ub.UserLibraryBook.user_id == user_id

ub.UserLibraryBook.book_id == book_id

So supplying another book ID does not let the caller remove another user's membership.

removal_impact() follows the same pattern. It first verifies that the requested book belongs to the current user's library, and its shelf query is also restricted to that user's shelves.

Final assessment:

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/d43be8cdac27a7a99caf7bd0643fbc4ea3cca546/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20211144.png)

The important research result is not that we discovered an IDOR. We discovered an authorization-control inconsistency worth carrying forward:

Some book-ID operations explicitly validate book visibility, while the default read-status and archive-state paths do not visibly perform equivalent validation within their helper functions.

That becomes a testing hypothesis for later labs.

We already mapped reverse-proxy authentication, so we'll focus primarily on OAuth/OIDC and LDAP.

**Find the authentication code**

Run: Select-String -Path .\cps\*.py -Pattern "oauth|oidc|ldap" | Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/8e08eb4735febecaf77b640219a4fea2e171af3a/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20213228.png)

This may produce a lot of output. That's okay—we're initially locating the relevant files.

Then run:Get-ChildItem .\cps -Filter "*oauth*"

And: Get-ChildItem .\cps -Filter "*ldap*"

What we're looking for

We're mapping these trust boundaries:

External Identity Provider

        ↓
        
OAuth / OIDC / LDAP

        ↓
        
Identity information received

        ↓
        
Identity validated

        ↓
        
Existing local user?

     ↙        ↘
     
   Yes         No
   
    ↓           ↓
    
Login       Account creation?

        ↓
        
Local authenticated session

We specifically want to identify where the application validates external identity, how an external identity maps to a local account, whether automatic account creation exists, and whether privileges are assigned during that process.

The search worked and already narrowed the important code significantly.

For OAuth/OIDC, the most important file is clearly cps\oauth_bb.py. It contains the generic OIDC session, claim handling, group-access authorization, user registration, user-info retrieval, and local-account mapping logic.

For LDAP, configuration and validation logic appears in admin.py, including provider URL, authentication settings, service-account configuration, group filtering, and user-object configuration.

**Inspect OAuth/OIDC identity mapping**

Run: Get-Content .\cps\oauth_bb.py | Select-Object -Skip 320 -First 150

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/a9cc68f703f46b4c002f0dbae61c156b017fd44c/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20214120.png)

This should show us the code around:

register_user_from_generic_oauth()

        ↓
        
OIDC userinfo retrieval

        ↓
        
Claim extraction

        ↓
        
Existing-user matching

        ↓
        
Group authorization

        ↓
        
Local account creation/linking

        ↓
        
Role assignment

We're especially interested in how an externally supplied OIDC identity becomes associated with a local Calibre-Web account. That's a major authentication trust boundary.

this gives us the key OAuth/OIDC trust-boundary logic we needed.

The flow is:

OIDC provider
   ↓
Access token
   ↓
userinfo endpoint
   ↓
Required claims: username + sub
   ↓
Existing local account lookup
   ↓
Group authorization check
   ↓
Role assignment / account creation
   ↓
OAuth binding + local session

A few controls stand out.

First, the application does not blindly trust a username alone. It requires both a mapped username field and the OIDC sub claim before continuing. That is a positive control because sub is intended to be the provider-side stable subject identifier.

Second, group authorization happens before account creation or login. The code explicitly checks the configured group claim and can reject the login before provisioning a user. That is a strong boundary.

Third, admin role assignment is conditional. A user only gets admin from the configured admin group when config_enable_oauth_group_admin_management is enabled. Otherwise, the user gets the configured default OAuth role. That reduces accidental privilege escalation from group claims.

The most interesting area for later testing is account matching. When not linking an already-authenticated user, the code first tries:

ub.User.name == provider_username

and if that fails, it falls back to:

ub.User.email == provider_email

That is important because external identity → existing local account matching is a sensitive trust boundary. We are not calling it a vulnerability, but it is worth deeper validation later, especially around whether the identity provider guarantees the email claim is verified and unique.

Current OAuth/OIDC assessment:

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/60cce90afe962b8d450dc6bc29a9627b3e8ed325/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20214834.png)

We still need the rest of the function because your output cuts off right after:

# Apply default user settings

Run: Get-Content .\cps\oauth_bb.py | Select-Object -Skip 450 -First 120

That should finish the provisioning and OAuth-binding logic. After that, we can close the OAuth portion and move to LDAP authentication mapping.

the second half completes the OAuth/OIDC mapping.

The application creates new OAuth users with configured default permissions and restrictions, rather than automatically giving broad privileges. For existing users, admin privileges can be granted or revoked based on current OIDC group membership, but only when OAuth group-based admin management is enabled.

Most importantly, after the local user is determined, the application creates or retrieves an OAuth record using both the provider ID and provider_user_id (sub), then associates that OAuth identity with the local user. That's an important security control.

OAuth/OIDC conclusion

No confirmed vulnerability.

Our main deeper-testing candidate remains:

External identity → existing local account matching, particularly the username/email fallback that occurs before the OAuth sub is ultimately bound to the account.

That doesn't mean it's vulnerable. It means it's worth testing later under controlled conditions.

Your earlier command: Get-ChildItem .\cps -Filter "*ldap*"


returned no dedicated LDAP-named Python file, so we'll locate the actual authentication functions instead.

Run this next: Select-String -Path .\cps\*.py -Pattern "ldap_bind|ldap_search|ldap_login|ldap_auth|LDAP" | Select-Object Path, LineNumber, Line

![Image alt](![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/95f44b4f55a57474754669f8befbf81d20cc88a1/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20215511.png))

This output found the actual LDAP login path.

The most important discovery is that LDAP authentication is handled primarily in cps\web.py around lines 3025–3101. The code appears to validate the username, attempt LDAP authentication, optionally retrieve LDAP user details and auto-create a local account, and handle local fallback behavior.

We also found a second LDAP authentication path in usermanagement.py, including LDAP authentication and automatic creation of new LDAP users

**Inspect the main LDAP login flow**

Let's examine web.py first. Run: Get-Content .\cps\web.py | Select-Object -Skip 3010 -First 110

We're looking for this boundary:

Username + Password

        ↓
        
Username validation

        ↓
        
LDAP authentication

        ↓
        
LDAP accepted?

   ↙             ↘
   
 Yes              No
 
  ↓                ↓
  
Find local user   Failure / controlled fallback

  ↓
  
Local user exists?

 ↙             ↘
 
Yes              No

 ↓                ↓
 
Login        LDAP auto-create enabled?

                    ↓
                    
             Retrieve LDAP identity
             
                    ↓
                    
             Create local account
             
                    ↓
                    
                  Login

One item is already worth noting for later: the search results show explicit local fallback behavior when LDAP is unavailable or rejects credentials. We need the surrounding code before deciding whether that's simply an intentional configuration feature or something that deserves deeper testing.

No LDAP vulnerability has been identified. We're still mapping the authentication boundary.

This confirms the main LDAP authentication flow, and there is one particularly important behavior to carry forward into later testing.

The normal successful path is:

Username + Password
        ↓
LDAP bind_user()
        ↓
LDAP authentication succeeds
        ↓
Does local account exist?
      ↙        ↘
    Yes         No
     ↓           ↓
   Login     Auto-create enabled?
                 ↓
          Get LDAP user details
                 ↓
          Create local account
                 ↓
               Login

The code has several good controls: it rejects empty usernames, requires LDAP authentication before LDAP auto-provisioning, retrieves LDAP user information before creating a new account, excludes the Guest account from local fallback, and records failed LDAP authentication attempts.

Important research candidate

The most security-relevant behavior is this branch:

elif login_result is False and user and user.password \
        and check_password_hash(str(user.password), form['password']) \
        and user.name != "Guest":

This means that even when the LDAP server is reachable and explicitly rejects the credentials, Calibre-Web NextGen can still authenticate that account using its stored local password.

That's different from fallback only when LDAP is unavailable.

For our research notes:

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/42f70c9e7f70d5fb37365c7acea57d5b910bdae6/Attack%20Surface%20Mapping/Screenshot%202026-09-03%20221748.png)

We should not classify this as an authentication bypass yet. It could be intentional design. But it creates a strong hypothesis for a later lab: if an administrator expects LDAP to be authoritative—for example, disabling an account in LDAP—could a pre-existing local password still allow that user to authenticate?

That is exactly the kind of question we'll test safely against the local installation during dynamic validation.

For Lab 3, we have mapped this boundary sufficiently.

Next we will build the Final Attack Surface Map, where we'll combine everything we've identified—login, uploads, admin routes, object authorization, remote login, reverse-proxy authentication, OAuth/OIDC, and LDAP—into one portfolio-quality map.

**Build the Final Attack Surface Map** 

We’re going to consolidate everything we discovered into one final map. This will become one of the main portfolio artifacts for the lab.

Our current map includes:

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/876072c29f9be74ce757911f072063a7635e3107/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20174915.png)

Our four primary hypotheses going forward

For later static and dynamic analysis, we've narrowed the large application down to four particularly useful areas:

OIDC account matching — username/email matching before the external sub identity is ultimately associated with the local account.

LDAP local fallback — LDAP can reject credentials while a valid stored local password may still authenticate the account.

Read-status object authorization — the default edit_book_read_status() path did not visibly perform the same book-visibility check used elsewhere.

Archive-status object authorization — change_archived_books() similarly did not visibly perform an object-visibility check.

These are research hypotheses, not vulnerabilities.


**Create the attack-surface document**

Go back to the project root. Run: cd C:\Users\eelve\Vulnerability-Research-Lab

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/7c9c226034ca61647e79447e077aaf431e3a4319/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20175350.png)

Your prompt should then show:

PS C:\Users\eelve\Vulnerability-Research-Lab>

Then create/open the attack-surface notes file: notepad .\notes\attack-surface-map.md

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/9bfa4310e002dde5336b626d013a1c526b2ccf90/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20175436.png)

Now paste the following into attack-surface-map.md exactly as shown:
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/95753bca22f4a00b13802737dd23ee3277e19f5f/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20175922.png)
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/441c3db45971cfd02ba5d970c14c11b16d021c50/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20175959.png
![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/18bba04145279bacfae8267fc3f3fce88b1e7cfc/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20180046.png)

Press Ctrl + S and close Notepad.

Then return to PowerShell and run: Get-Content .\notes\attack-surface-map.md

We want to verify that the file saved correctly before we commit it to Git.

run: Get-Content .\notes\attack-surface-map.md -Encoding UTF8

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/050082368c505ff7eab0e5f9b521452b7268a76f/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20181055.png)

**Check Git status** 

Run: git status

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/0255d6543ef92d64cbed404e97df333a220d32b2/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20181322.png)

This is a good catch. Do not run git add . because both notes/ and targets/ are untracked. We only want to add the Lab 3 attack-surface document right now.

Run: git add .\notes\attack-surface-map.md

Then: git status

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/b17e27ac1ee49ad5892c8bde52857cd1b6da8779/Screenshot%202026-09-07%20220855.png)

What we want to see is approximately:

Changes to be committed:

  new file:   notes/attack-surface-map.md

Untracked files:

  targets/

The targets/ directory should remain untracked for now, especially because it contains the separately cloned Calibre-Web NextGen repository.

That is exactly what we wanted. Your Git status shows:

Notes/attack-surface-map.md — staged and ready

Notes/target-selection.md — untracked

Targets/ — untracked and not being committed

Nothing unintended is staged

**Commit the Lab 3 Attack Surface Map**

Run: git commit -m "Document Lab 3 attack surface map"

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/65b2cb53cade6235d339782d68291c1fcfc4e23b/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20181808.png)

Then verify. Run: git status

Perfect. That confirms the attack surface map was committed successfully. The only remaining untracked items are notes/target-selection.md and targets/, so the Lab 3 file is no longer listed as untracked or modified.

**Final Review** 

Before we close Lab 3, let's verify the commit itself.

Run: git log --oneline -5

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/3603913ec264457e77bdee9219a4fec41ab14b5e/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20182229.png)

We should see your new commit near the top:

<commit-id> Document Lab 3 attack surface map

Then we'll do the final Lab 3 review, document what you accomplished, and prepare to move into Lab 4 — Static Analysis, where we'll begin using the four research hypotheses to guide Semgrep, CodeQL, and manual source-code analysis.

It's officially complete. Your Git history confirms:

b4ec634  Document Lab 3 attack surface map

8f5e89a  Add Semgrep static analysis tooling

8eea2cf  Set up vulnerability research environment

**Final Review**

At this point, Lab 3 has accomplished what we wanted. You manually mapped the application before relying on scanners, identified the major authentication, authorization, file-handling, and identity trust boundaries, documented existing security controls, and narrowed the research to four hypotheses without incorrectly labeling any of them vulnerabilities.

Your four candidates moving forward are:

OAuth/OIDC account matching

LDAP local-password fallback

Read-status object authorization

Archive-status object authorization

One cleanup item before we close Lab 3

Your git status previously showed:

notes/target-selection.md

targets/

target-selection.md is your Lab 2 documentation, so we should get that properly committed too rather than leave it untracked.

Run: git add .\notes\target-selection.md

Then: git status

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/99c1b9ebfdf4e6d5926324deb7f51c0f899cb164/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20182657.png)

We want target-selection.md staged while targets/ remains untracked.

The screenshot confirms the cleanup is exactly where we want it:

Notes/target-selection.md — staged

Targets/ — remains untracked

Lab 3 attack-surface map — already committed

**Commit the Lab 2 documentation**

Run: git commit -m "Document Lab 2 target selection"

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/9a0ee3101dc0354f6b9da46a7d5d8bb08c637a3d/README.md)

Then verify the repository: git status

![Image alt](https://github.com/Kevinolee1/Attack-Surface-Mapping/blob/f0dcfbc51c570008a4c69de5036bdc80b75686b4/Attack%20Surface%20Mapping/Screenshot%202026-09-04%20183026.png)

And check the history: git log --oneline -5

Perfect. Both screenshots confirm the cleanup was successful.

Your Git history now shows:

8960eba  Document Lab 2 target selection

b4ec634  Document Lab 3 attack surface map

8f5e89a  Add Semgrep static analysis tooling

8eea2cf  Set up vulnerability research environment

Your git status shows only:

Untracked files:

    targets/

That's intentional. The cloned Calibre-Web NextGen source repository remains separate from your main research repository.

You successfully documented the application architecture, mapped authentication and authorization boundaries, analyzed file-upload handling, reviewed remote login, OAuth/OIDC, LDAP, and object-level authorization, and identified four areas for deeper investigation without prematurely calling them vulnerabilities.
