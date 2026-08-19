# Why `commons.ui.version` is pinned, and what ends it — task 3.10

`openam-ui/openam-ui-ria/pom.xml` overrides the commons version. This file records why, and the
two conditions that end it. Neither is a plan or an intention — **each is a condition with a
command that answers it**, so it can be recomputed rather than trusted. Both were introduced by
the npm-packaging work (design decision D18) and both stop applying once tasks 3.11 and 3.12 have
run.

Written by task 3.10 of `modernize-openam-ui-build`, verified 2026-08-19 against this checkout,
the sibling `commons` checkout on `features/ui-migration`, Maven Central and the Central Portal
snapshot repository. Companion to `NOTES-npm-commons.md`, which records task 3.7's measurements
for the same wiring.

Section 2 is about the **upstream** commons release channel rather than about AM. It is recorded
here anyway, because the consequence lands on this module and nothing in the commons repository
should have to know that AM exists.

---

## 1. The pin, and only a commons release clears it

### The condition

`openam-ui/openam-ui-ria/pom.xml` sets

```xml
<commons.ui.version>3.2.0-SNAPSHOT</commons.ui.version>
```

That property is **build-blocking**, and it exists for exactly one reason: **no released commons
carries a `tgz:npm` artifact.** Remove it and there is no version at which the tarballs resolve at
all — the version the BOM chain manages is 3.1.2, which has none.

The pin is necessary but not sufficient. *With* it set and without `mvn install -f ui/pom.xml` in
the sibling commons checkout first, this module fails at `initialize` with

```
Could not find artifact org.openidentityplatform.commons.ui:commons:tgz:npm:3.2.0-SNAPSHOT
```

Read that message carefully before editing anything: it names the *pinned* version, so what it
reports is the missing local install, not a missing pin. The fix is to build commons first.

### Checking that reason rather than quoting it

The latest release is 3.1.2, and it ships `www` only:

```
$ curl -s https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/commons/maven-metadata.xml \
    | grep -o '<version>[^<]*</version>' | tail -3
<version>3.1.0</version>
<version>3.1.1</version>
<version>3.1.2</version>

$ curl -s https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/commons/3.1.2/ \
    | grep -o 'href="[^"]*"' | sed 's/href=//' | grep -vE '\.(asc|md5|sha1|sha256|sha512)"'
"../"
"commons-3.1.2-www.zip"
"commons-3.1.2.pom"
```

There is no `commons-3.1.2-npm.tgz`, and the same holds for `user`. Locally, `~/.m2` tells the
same story from the other side: `commons/3.1.2/` holds `commons-3.1.2-www.zip` and no
`-npm.tgz`, while the locally installed `commons/3.2.0-SNAPSHOT/` does hold
`commons-3.2.0-SNAPSHOT-npm.tgz`.
The pin is therefore not a preference; it is the only way to reach an artifact that exists
nowhere but a developer's `~/.m2`.

### The pin is a version *split*, and that is the part worth recording

`commons.ui.version` reaches **only** the two `artifactItem`s of the `copy-commons-npm-tarballs`
execution. It does not reach the declared `commons.ui` dependency, which carries no `<version>`
element and takes its version from the imported BOM chain (`pom.xml` `dependencyManagement` at
the OpenAM root, `opendj-parent` at `<scope>import</scope>`). A `scope=import` BOM interpolates
its properties inside itself, so an override in the consuming pom cannot reach it.

The resolved graph shows the split directly:

```
$ cd openam-ui/openam-ui-ria && mvn -o dependency:list -DoutputFile=target/deplist.txt
$ grep -i 'commons\.ui' target/deplist.txt | grep -v 'commons\.ui\.libs'
   org.openidentityplatform.commons.ui:user:zip:www:3.1.2:compile
   org.openidentityplatform.commons.ui:commons:zip:www:3.1.2:compile
```

Two things to read off that output:

- **The BOM chain gives this module 3.1.2**, not `3.2.0-SNAPSHOT`. The build composes AMD
  sources at 3.2.0-SNAPSHOT over vendor libraries still resolved at 3.1.2. 58 of the 63 lines in
  that file are `commons.ui.libs` artifacts, and **neither half of them moves with
  `commons.ui.version`**: 33 arrive transitively through the 3.1.2 `user:zip:www` and track the
  BOM-managed commons version (`dependency:tree` shows these nested under it, and
  `pom.xml:66-72` records the same 33), while the other 25 are declared directly in this pom
  (`openam-ui-ria/pom.xml:82-250`) with hard-coded `<version>` elements and track nothing at
  all. **Nothing checks any of it agrees**, and a vendor-library bump in commons 3.2 reaches
  neither set. The distinction matters to task 4.7: retiring the `zip:www` dependency detaches
  the 33, and leaves the 25 exactly where they are.
- **No `tgz:npm` appears at all.** The tarballs are `maven-dependency-plugin` `artifactItem`s,
  not dependencies, so they are invisible to `dependency:list`, `dependency:tree` and to every
  tool that walks the dependency graph. In this module's resolved graph the only trace of the
  coupling is its absence.

### What clears the pin — both halves, not either

1. A commons **release** carrying `tgz:npm` at both `commons` and `user`; **and**
2. **This module's managed version moving onto that release** — the version the BOM chain
   manages, not the property override.

Condition 1 alone removes the build-blocking prerequisite but leaves the split in place.
Condition 2 alone is impossible while the released version has no tarball. Task **3.12** is where
the pin and the `copy-commons-npm-tarballs` execution are removed together, after task 3.11 has
published to the npm registry and consumption has moved to a registry range.

### How to check whether the pin is still needed

Run these from the **OpenAM repository root**, not from the directory this file sits in.

```
# 1. Does a released commons carry the artifact yet?
curl -sI -o /dev/null -w '%{http_code}\n' \
  https://repo1.maven.org/maven2/org/openidentityplatform/commons/ui/commons/<version>/commons-<version>-npm.tgz

# 2. Is this module still overriding the version?
grep -n 'commons.ui.version' openam-ui/openam-ui-ria/pom.xml

# 3. What does the BOM chain actually give it?
cd openam-ui/openam-ui-ria && mvn -o dependency:list -DoutputFile=target/deplist.txt \
  && grep -i 'commons\.ui' target/deplist.txt | grep -v 'commons\.ui\.libs'
```

If (1) returns `200` and (3) reports that same version, the pin is dead weight and 3.12 can run.
If (1) returns `404`, the pin is still load-bearing and removing it breaks this build.

---

## 2. Upstream: every successful commons master build deploys, and a release burns the coordinates

All paths in this section are in the **sibling commons checkout**, not this one.

### The condition

`.github/workflows/deploy.yml` deploys to OSSRH on every successful `master` build, with no
per-artifact opt-in. Verified from the file rather than assumed:

```yaml
# .github/workflows/deploy.yml:4-7
  workflow_run:
    branches: [ 'sustaining/2.4.x','master' ]
    workflows: ["Build Maven","Release Maven"]
    types: [completed]

# :16
    if: ${{ github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event=='push' }}

# :49-55
      - name: Publish to the Maven Central Repository
        run: mvn --batch-mode --errors --update-snapshots -Dgpg.passphrase=*** deploy --file pom.xml
```

`Build Maven` (`build.yml:4-5`) fires on every push to `master`, so the chain is: push → build →
deploy. One caveat worth knowing: the `workflow_run.event=='push'` guard means the
**workflow_dispatch-triggered `Release Maven` run does not reach this job** — `release.yml`
deploys on its own, through `release:prepare release:perform`.

`mvn deploy` deploys *every attached artifact*, and the tarball is attached in the default
build — not behind a profile:

```
ui/commons/pom.xml:158-180   build-helper-maven-plugin, execution attach-npm-tarball,
ui/user/pom.xml:170-192      phase package, <type>tgz</type> <classifier>npm</classifier>
```

So once this is on commons `master`, the `tgz:npm` artifact deploys automatically with everything
else. Nobody has to decide to publish it; somebody has to decide *not* to.

### It is not armed yet — re-check this, it is the fastest-moving fact here

```
$ git fetch origin                                                    # origin/master is a cache
$ git show origin/master:ui/commons/pom.xml | grep -c attach-artifact
0
```

Without the fetch this reports whatever the last fetch saw, which is how a reader concludes "not
armed" a month after it armed.

The attach lives only on `features/ui-migration`. The published snapshot confirms it: the
Central Portal snapshot metadata for `3.2.0-SNAPSHOT` (build 14, 2026-08-10) lists `pom` and
`www`-classified `zip` only, with no `npm` classifier. **No `tgz:npm` has ever been deployed
anywhere.** It arms the moment `features/ui-migration` merges to commons `master`, with no
further action and no separate review of that fact.

### The asymmetry

- **The snapshot lane overwrites freely.** `3.2.0-SNAPSHOT` lands in the Central Portal
  snapshot repository, `https://central.sonatype.com/repository/maven-snapshots/` — which the
  commons root `pom.xml:73-85` also declares as the `<repositories>` source, so that project both
  publishes to and consumes from it. There is no `<distributionManagement>` block in that tree at
  all; the target comes from `central-publishing-maven-plugin`'s `publishingServerId=ossrh`.
  Snapshots are timestamped and re-deployed on every master push — currently at build 14. This
  is the rehearsal channel D18 depends on, and it is why the phase-1 gate (task 3.8) can run
  *before* anything irreversible.
- **A release goes to Maven Central and is immutable.** It burns these coordinates exactly as
  npm burns a version. `central-publishing-maven-plugin` is configured `<autoPublish>true</autoPublish>`
  (commons root `pom.xml:1430-1440`), so there is no manual staging-release gate to catch a
  mistake between deploy and publication.

**`"private": true` does not protect this.** It is in both commons `package.json` files and it
does stop `npm publish`. It stops nothing else: **`npm pack` ignores it entirely** — which is why
this channel exists at all, the packed `-npm.tgz` in `~/.m2` carrying `"private": true` on line 6
of its own `package.json` — and `mvn deploy` never reads `package.json` in the first place. (The
`//private` comment beside the flag in both `package.json` files says `npm pack` "honours" it.
That wording is wrong in the same way, and is left for whoever next has licence to edit those
files.)

D18's argument that a bad `files` list "is fixed by rebuilding, not by burning another version"
holds for the npm registry and **does not hold for Maven Central**: a released `3.2.0` tarball
with a wrong payload is fixed by releasing `3.2.1`.

### What that means if a commons release is cut before task 3.12 has run

In the commons checkout, `git fetch origin && git show origin/master:ui/commons/pom.xml | grep -c
attach-artifact` says which of these two cases applies: `0` is A, non-zero is B. (`git log
origin/master -- ui/commons/pom.xml ui/user/pom.xml` then says *when* it landed.) Both cost this
module something.

**A — the attach is still off commons `master`.** The release carries no `tgz:npm`, so it cannot
clear the pin above; that version number is burned without the artifact and this module can never
pin to it. Worse, `release:prepare` moves the commons working version to the `developmentVersion`
input (e.g. `3.2.1-SNAPSHOT`), so a subsequent `mvn install -f ui/pom.xml` installs
`3.2.1-SNAPSHOT` and this module's `commons.ui.version=3.2.0-SNAPSHOT` resolves to nothing — the
build fails at `initialize` with the "Could not find artifact" error above, until someone edits
this pom. Two things delay that failure without preventing it: `release:prepare` pushes the bump
to commons `master`, so a checkout on `features/ui-migration` is unaffected until it takes that
bump; and a `~/.m2` that still holds the old `3.2.0-SNAPSHOT` keeps resolving it. **So a commons
release cut from that state invalidates this build on a clean machine first, and on the machine
that cut it possibly not at all.**

**B — the attach has landed but task 3.8 is not yet green.** (3.8 is the phase-1 gate; it is
green only if it is marked `[x]` in the change's `tasks.md`, and after the change is archived,
in the archived copy.) The release publishes to Central packages that the gate has not proven.
D18's entire ordering argument — put the gate in front of the step that cannot be taken back —
is defeated by the Maven release even though no `npm publish` ever ran. The npm registry is
protected by `"private": true`; Central is not protected by anything.

---

*Both conditions above are temporary by construction. Task 3.11 publishes to the npm registry
and writes the commons-side release documentation; task 3.12 moves this module to a registry
range, drops the pin and the `copy-commons-npm-tarballs` execution, and decides whether the
`tgz:npm` artifact stays at all. **The check that this file is spent is mechanical, and does not
depend on the task numbers outliving the change:** if `grep -c commons.ui.version
openam-ui/openam-ui-ria/pom.xml` returns `0` and `copy-commons-npm-tarballs` is gone from that
pom, 3.12 has run — delete this file. A note outliving the coupling it describes is how the
coupling becomes permanent.*
