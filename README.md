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
