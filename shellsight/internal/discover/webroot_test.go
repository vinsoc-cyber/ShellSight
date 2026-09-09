package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPhysicalPathsWithEnvExpansion(t *testing.T) {
	t.Setenv("SystemDrive", "C:")
	xml := []byte(`<sites>
  <site name="Default Web Site" id="1">
    <application path="/"><virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" /></application>
  </site>
  <site name="app" id="2">
    <application path="/"><virtualDirectory path="/" physicalPath="D:\sites\app" /></application>
  </site>
</sites>`)
	got := extractPhysicalPaths(xml)
	if len(got) != 2 {
		t.Fatalf("want 2 paths, got %d: %v", len(got), got)
	}
	if got[0] != `C:\inetpub\wwwroot` {
		t.Fatalf("env not expanded: %q", got[0])
	}
	if got[1] != `D:\sites\app` {
		t.Fatalf("literal path wrong: %q", got[1])
	}
}

func TestExplicitWebrootsWin(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "site")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got := Webroots([]string{sub, filepath.Join(dir, "does-not-exist")})
	if len(got) != 1 || got[0] != filepath.Clean(sub) {
		t.Fatalf("explicit existing-dir filter failed: %v", got)
	}
}

// Apache DocumentRoot appears once per vhost, quoted or bare, and commented lines
// (and trailing comments) must be ignored. This is where PHP most commonly lives.
func TestApacheDocumentRootsParse(t *testing.T) {
	conf := []byte(`# main config
DocumentRoot "/var/www/html"
<VirtualHost *:80>
    ServerName a.example
    DocumentRoot /srv/sites/a          # the A site
</VirtualHost>
# DocumentRoot /this/is/commented/out
<VirtualHost *:443>
    DocumentRoot "/srv/sites/b"
</VirtualHost>`)
	got := apacheDocumentRoots(conf)
	want := []string{"/var/www/html", "/srv/sites/a", "/srv/sites/b"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("root %d: want %q got %q (all: %v)", i, want[i], got[i], got)
		}
	}
}

// nginx `root` lives inside server/location blocks, ends at `;`, and must not be
// confused with other *_root directives or picked up from comments.
func TestNginxRootsParse(t *testing.T) {
	conf := []byte(`http {
    server {
        root /usr/share/nginx/html;
        location /app {
            root "/var/www/app";     # quoted, indented
        }
        # root /commented/out;
        fastcgi_temp_path /var/cache;   # not a root
    }
}`)
	got := nginxRoots(conf)
	want := []string{"/usr/share/nginx/html", "/var/www/app"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("root %d: want %q got %q (all: %v)", i, want[i], got[i], got)
		}
	}
}

// A bare drop-and-run on a typical LAMP box (no explicit --path) must still find the
// conventional webroots. The candidate list is where PHP is found without any config.
func TestLinuxDefaultWebrootsCoverConventionalPaths(t *testing.T) {
	got := linuxDefaultWebroots()
	for _, need := range []string{"/var/www/html", "/var/www", "/srv/www", "/usr/share/nginx/html"} {
		found := false
		for _, g := range got {
			if g == need {
				found = true
			}
		}
		if !found {
			t.Errorf("conventional webroot %q missing from defaults %v", need, got)
		}
	}
}

// In a split install, CATALINA_HOME (binaries) and CATALINA_BASE (instance,
// where webapps actually live) differ and BOTH must be scanned.
func TestTomcatWebrootsUsesBothEnvs(t *testing.T) {
	t.Setenv("CATALINA_HOME", `C:\tomcat\home`)
	t.Setenv("CATALINA_BASE", `C:\tomcat\base`)
	got := tomcatWebroots()
	if len(got) != 2 {
		t.Fatalf("want webapps for both HOME and BASE, got %v", got)
	}
	if got[0] != filepath.Join(`C:\tomcat\home`, "webapps") || got[1] != filepath.Join(`C:\tomcat\base`, "webapps") {
		t.Fatalf("unexpected tomcat roots: %v", got)
	}
}
