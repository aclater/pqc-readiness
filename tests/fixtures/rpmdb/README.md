# rpm database fixtures

| Dir | Format | Built from | How |
| --- | --- | --- | --- |
| `el9/`, `fedora44/`, `ol9-stray-empty/` | SQLite | real images (#125) | see `tests/test_rpmdb.py` |
| `el8-bdb/` | Berkeley DB hash (`Packages`, gzipped) | `registry.access.redhat.com/ubi8/ubi`, rpm 4.14.3 | `rpm --initdb --dbpath /tmp/db`; `dnf download nss libgpg-error.x86_64`; `rpm --dbpath /tmp/db -i --justdb --nodeps --noscripts --notriggers --nosignature *.rpm`; `rpm --dbpath /tmp/db --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release` |
| `suse-ndb/` | ndb (`Packages.db`, gzipped) | `registry.opensuse.org/opensuse/leap:16.0`, rpm 4.20.1 | same, with `zypper download mozilla-nss libgpg-error0` and a key from `/usr/lib/rpm/gnupg/keys/` |

`expected-rpm-qa.txt` is `rpm --dbpath /tmp/db -qa --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' | sort`
from the same container. The binary databases are gzipped to keep the
repository small; tests decompress them into a temporary host root.
