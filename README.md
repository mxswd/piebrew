# piebrew

Homebrew bottles installed as dpkg packages.

```
piebrew install htop      # brew-ncurses, then brew-htop
piebrew list
piebrew outdated
piebrew upgrade
piebrew remove htop
```

piebrew asks Homebrew's API (formulae.brew.sh) for a formula, fetches its
arm64 bottle from ghcr.io into memory, checks its SHA-256, and makes
a `.deb` of it in memory: the keg under `/opt/homebrew/Cellar`, relocated
as brew does (the `@@HOMEBREW_*@@` placeholders in text files and in
Mach-O load commands), every Mach-O file signed again ad hoc with 4 KB
pages (the BCM2711 kernel takes no other size), a system library the
system lacks and a file imports nothing from weak-linked (gnulib's
CoreServices link, in libunistring, gettext, ...), and brew link's symlinks
in `/opt/homebrew/{bin,lib,share,...}`. dpkg installs it as
`brew-<formula>`, depending on its dependencies' `brew-` packages and on
the system packages owning the libraries it loads, so dpkg and apt list,
remove and upgrade it. See `piebrew.1`.

BSD-2-Clause (LICENSE); cJSON is MIT (cjson/LICENSE).
