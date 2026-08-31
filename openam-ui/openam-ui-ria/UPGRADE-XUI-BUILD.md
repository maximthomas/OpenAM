---
title: "Upgrading the XUI: configuration is now built into the application"
audience: operators upgrading an existing deployment
citation: 'XUI upgrade note: openam-ui/openam-ui-ria/UPGRADE-XUI-BUILD.md in the OpenAM source tree, or https://github.com/OpenIdentityPlatform/OpenAM/blob/master/openam-ui/openam-ui-ria/UPGRADE-XUI-BUILD.md'
---

<!--
  The `citation` field above is the exact string the XUI prints to the browser console to point an
  operator at this note. It is ASCII-only, carries no trailing punctuation and no URL fragment, so
  that it survives being read off a console and typed by hand. If this file is renamed or moved,
  that string and the console message must change together.
-->

# Upgrading the XUI: configuration is now built into the application

**If you customized this deployment by editing files under `<webapp>/XUI/config/`, those edits stop
working after the upgrade.** The `config/` directory is no longer part of a deployed XUI at all.
`AppConfiguration.js` and `ThemeConfiguration.js` — and the fifteen other files that sat beside
them, including the route configuration, the process configuration, the validators and the message
definitions — are now compiled into the application itself. There is nothing left on the server to
edit. An upgraded instance that still contains a `config/` directory is reading none of the files
that used to be there: they are inert, nothing reports an error, and the UI runs on the
configuration that was built into it.

This is a one-way change. Configuration is now customized by editing it in the product source and
rebuilding.

If you have never edited anything under `<webapp>/XUI/`, nothing in this note requires action from
you.

## Before you upgrade

Take a copy of your deployed `<webapp>/XUI/config/` directory. It is the only record of what you
customized, and the upgrade replaces the tree it lives in. You will need it to reproduce those
settings in the product source — as a record of your **values**, not as files to copy back. The
source files have the same names and the same settings in the same places, but a different module
format; see step 1 below.

Also note anything you added or edited elsewhere under `<webapp>/XUI/`. Most of it survives — see
[What still works without a rebuild](#what-still-works-without-a-rebuild) — but files you *added*
are removed if you replace the tree, so keep a copy of those too.

## The replacement workflow

1. **Edit the configuration in the product source.**

   ```
   openam-ui/openam-ui-ria/src/main/js/config/AppConfiguration.js
   openam-ui/openam-ui-ria/src/main/js/config/ThemeConfiguration.js
   ```

   These hold the same settings, under the same names, in the same structure as the files you were
   editing on the server. **Transfer your values into them; do not copy your saved files over
   them.** The deployed copies were wrapped for the old module system — they began `define({` or
   `define([], function () {` — and the source files are ES modules ending in `export default`.
   Overwriting a source file with a saved deployed copy produces a module that exports nothing, and
   the UI will fail to start.

   One value in `AppConfiguration.js` has no literal in the source: `loginHelperClass` is filled in
   from a placeholder when the application is built. If you had customized it, replace that
   placeholder with your own identifier as a quoted string.

   Ten of the seventeen files you had under `config/` have a counterpart here, at the same relative
   path: `AppConfiguration.js`, `ThemeConfiguration.js`, `AppMessages.js`, `main.js`,
   `process/AMConfig.js`, `routes/AMRoutesConfig.js`, `routes/admin/GlobalRoutes.js`,
   `routes/admin/RealmsRoutes.js`, `routes/user/UMARoutes.js` and `validators/AMValidators.js`.
   Anything else under `src/main/js/` is customizable the same way.

   The other seven — `routes/CommonRoutesConfig.js`, `routes/UserRoutesConfig.js`,
   `process/CommonConfig.js`, `validators/CommonValidators.js`, `messages/CommonMessages.js`,
   `messages/UserMessages.js` and `errorhandlers/CommonErrorHandlers.js` — have no counterpart in
   the OpenAM source tree. They come from the shared commons UI packages that this module depends
   on. If you had customized one of those, this workflow does not cover it: please raise an issue
   describing what you changed, rather than assuming a source file exists to edit.

2. **Build the UI module.**

   ```
   cd openam-ui/openam-ui-ria
   mvn -DskipTests package
   ```

   Use this command, not the `npm run build:production` script it calls. Run on its own, the npm
   script does not receive the product version, and the UI then serves every deployment under a
   single cache key — after which browsers hold on to templates from the previous version. The
   Maven build supplies the version.

3. **Collect the artifact.**

   ```
   openam-ui/openam-ui-ria/target/openam-ui-ria-<version>-www.zip
   ```

   The archive contains the deployed tree at its root: its paths are already the paths under
   `/XUI`, with no wrapping directory.

4. **Deploy it.**

   If you build the whole server, this artifact is already consumed by the server build and
   unpacked into the war — no separate step is needed, and the deployed `/XUI` is replaced whole.

   To update an existing instance in place, **delete `<webapp>/XUI` and unpack the archive in its
   place.** Unpacking over the existing directory instead only merges: the old configuration files
   stay behind, and every previous build's application files accumulate under `assets/`.

   Either way the tree is replaced, so **anything you added yourself is gone** — a module you
   dropped in, a theme asset you added, an edited stylesheet. Put those back afterwards from the
   copies you took.

   If you do choose to unpack over the existing tree, delete the leftover configuration files from
   `<webapp>/XUI/config/` yourself — keeping any module of your own that lives there, see
   [Adding your own module](#adding-your-own-module). Nothing reads the configuration files, and
   leaving them in place makes the next person believe they are live.

Do not copy individual files out of a new build into an old deployed tree: the application payload
under `assets/` is split across files whose names contain a hash of their contents, so those names
change whenever the contents do, and a partial copy leaves the instance loading a mixture of two
builds.

## What still works without a rebuild

Theme stylesheets, images, templates and partials remain individually addressable files in the
deployed instance, at the same paths as before, with no hashes in their names. You can add or
replace any of them on a deployed server, without rebuilding and without redeploying:

| directory | files | what it holds |
|---|---:|---|
| `templates/` | 198 | page and view templates |
| `partials/` | 29 | template fragments |
| `themes/` | 4 | the assets of the shipped non-default theme |
| `css/` | 10 | stylesheets |
| `images/` | 19 | images |
| `locales/` | 3 | translated strings |

`index.html`, `oauthReturn.html`, `timezones.json`, `favicon.ico` and the `libs/` directory also
remain at their existing paths, unhashed.

The override mechanism is unchanged: placing a file under the asset path of a registered theme
still causes it to be served in place of the base file, and it takes effect on the next request for
that template. Editing a stylesheet in place still reaches clients that have not cached the
previous version.

What requires a rebuild is *registering* a theme and *choosing* which realms and authentication
chains it applies to, because that is configuration and configuration is now built in. The assets
of a theme that is already registered are yours to edit on the server.

The installation guide's "Customizing the XUI" chapter, and the XUI parameters reference, still
instruct you to edit `/path/to/tomcat/webapps/openam/XUI/config/ThemeConfiguration.js` to register
a theme and map it to realms. **This note supersedes those instructions**: make that edit in the
product source as described above. The rest of those chapters — the theme's stylesheets, images,
templates and partials — still holds.

## Adding your own module

**You can still add a module to a deployed instance. You can no longer name one without a
rebuild.** Both halves are true, and they are about two different files.

*Adding it still works.* The UI still resolves module identifiers it did not know about when it was
built. If the configuration names `config/MyLoginHelper`, the UI fetches
`/XUI/config/MyLoginHelper.js` from the deployed tree at runtime, exactly as before, and dropping
that file onto a deployed instance is still a file copy.

*The file itself must be written differently.* It has to be a self-contained ES module with a
default export. A module written for the old loader — one whose body is `define([...], function
() {...})` — is fetched and parsed without complaint and then fails when it runs, because `define`
no longer exists. Rewriting it is usually mechanical: drop the wrapper and export the object.

One thing that cannot be carried across: a module that reached a shipped module by identifier, for
example by extending `org/forgerock/openam/ui/user/login/RESTLoginHelper`, has no way to reach it
any more — the shipped modules are inside the application bundle and are not addressable by name
from outside it. Such a module has to be rewritten to stand on its own.

If you ship more than one file, note that the UI requests your module with a version query string
appended. A relative import from inside your own module — `import("./Other.js")` — inherits the
directory but not that query, and the same file fetched at two different URLs is loaded and
evaluated twice. Give each file its own module identifier rather than importing siblings by
relative path.

*Naming it does not work any more.* The file that did the naming was `config/AppConfiguration.js`,
and that file is no longer deployed — it is compiled into the application. So there is nothing on
the server to edit that would point the UI at your module. Naming it is a source change and a
rebuild, per the workflow above.

Two consequences worth planning for. Replacing the tree **removes any module you dropped in** —
keep your copy and put it back afterwards. And editing the built application in place is not a
substitute: the hash in each filename describes the contents of that file, so changing the contents
makes the name wrong.

## What else is no longer deployed

Nothing under `org/` (303 files), `store/` (6) or `components/` (5) is deployed any more; those
directories held the bulk of the application and are now inside the bundle, so a change patched
into one of them on a server is gone and does not survive the upgrade.

## Summary

| you did this before | you do this now |
|---|---|
| edit `<webapp>/XUI/config/AppConfiguration.js` | edit `src/main/js/config/AppConfiguration.js`, rebuild, redeploy |
| edit `<webapp>/XUI/config/ThemeConfiguration.js` | edit `src/main/js/config/ThemeConfiguration.js`, rebuild, redeploy |
| edit one of the other eight AM configuration files | edit its counterpart under `src/main/js/config/`, rebuild, redeploy |
| edit one of the seven `Common*`/`User*` configuration files | not covered by this workflow — raise an issue |
| add a theme's stylesheets, images, templates, partials | unchanged — edit them in the deployed instance |
| override a template or partial for a registered theme | unchanged — place the file in the deployed instance |
| drop a module into the deployed tree | still works, but it must be an ES module, a redeploy removes it, and naming it needs a rebuild |
