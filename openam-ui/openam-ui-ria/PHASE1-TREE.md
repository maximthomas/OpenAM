# PHASE1-TREE.md — the Grunt-built `target/compiled` manifest

**Captured while the Grunt pipeline is still live.** This is the acceptance oracle for tasks
4.4–4.8: it is what a Vite build has to be compared against, and it cannot be regenerated once
task 4.1 flips the build. Do not delete or regenerate it after that point.

Produced by task 4.0 (survey and spike). No source file, pom, `package.json` or `Gruntfile.js`
was modified to produce it.

## Provenance

| | |
|---|---|
| Tree | `OpenAM/openam-ui/openam-ui-ria/target/compiled` |
| Produced by | `grunt prod` → `build`, driven by `frontend-maven-plugin` execution `npm-build` (`npm run build:production -- --target-version=${project.version}`) |
| Packed by | `src/main/assembly/zip.xml`, `<directory>target/compiled</directory>` → `<outputDirectory>/</outputDirectory>`, into `openam-ui-ria-<version>-www.zip` |
| Version stamped | `16.2.0-SNAPSHOT` (`index.html`, `urlArgs: "v=16.2.0-SNAPSHOT"`) |
| Digest | md5 per file, plus byte size |
| Files | **652** |
| Total bytes | **7,217,101** |

`zip.xml` maps this directory to the archive root with no top-level folder, so every path below
is also its path inside the `-www.zip` and its path under `/openam/XUI/` on a deployed instance.

## 1. Shape at a glance

- **652 files**, 7,217,101 bytes, in 11 top-level directories plus 8 root files.
- **384 are JavaScript** (`.js`). **268 are static assets** that must be copied verbatim.
- The tree is **not** "a bundle plus assets". It is a *partial* bundle plus a full unbundled
  module tree — see §4, which is the single most important fact in this file.

### By extension

| Extension | Files | Class |
|---|---:|---|
| `.js` | 384 | JavaScript |
| `.html` | 229 | static (template, fetched at runtime by path) |
| `.png` | 20 | static |
| `.css` | 6 | static (LESS output or vendor) |
| `.json` | 6 | static |
| `.otf` | 1 | static (font) |
| `.eot` | 1 | static (font) |
| `.svg` | 1 | static |
| `.woff` | 1 | static (font) |
| `.woff2` | 1 | static (font) |
| `.ico` | 1 | static |
| `.map` | 1 | source map |

## 2. Top level

| Path | Files | of which `.js` | Bytes | What it is |
|---|---:|---:|---:|---|
| `(root)` | 8 | 3 | 2,174,459 | `index.html`, `main.js` + `.map`, `main-authorize.js`, `main-device.js`, `oauthReturn.html`, `favicon.ico`, `timezones.json` |
| `components/` | 5 | 5 | 10,224 | React components, AMD-wrapped from `.jsx` |
| `config/` | 17 | 17 | 92,219 | `AppConfiguration.js`, `ThemeConfiguration.js` and routes — **deliberately unbundled** (`excludeShallow`) so operators can edit them in place |
| `css/` | 10 | 0 | 1,121,945 | LESS output (`structure`, `theme`, `styles-admin`) plus vendor CSS and Font Awesome |
| `images/` | 19 | 0 | 99,234 | PNG assets, referenced from CSS and templates |
| `libs/` | 50 | 50 | 1,970,218 | vendor JavaScript, copied verbatim, never transpiled (`babel.options.ignore: ["libs/"]`) |
| `locales/` | 3 | 0 | 68,657 | i18next translation JSON, fetched at runtime by path |
| `org/` | 303 | 303 | 1,311,214 | the application and commons AMD module tree |
| `partials/` | 29 | 0 | 14,488 | Handlebars partials, fetched at runtime by path |
| `store/` | 6 | 6 | 8,861 | Redux store, actions and reducers |
| `templates/` | 198 | 0 | 202,513 | Handlebars templates, fetched at runtime by path — **overridable by operators on the deployed instance** |
| `themes/` | 4 | 0 | 143,069 | the `dark` theme tree, copied wholesale (`themes/**/*.*`) |
| **total** | **652** | **384** | **7,217,101** | |

## 3. One level down

| Path | Files | of which `.js` | Bytes |
|---|---:|---:|---:|
| `(root)` | 8 | 3 | 2,174,459 |
| `components/` | 5 | 5 | 10,224 |
| `config/` | 4 | 4 | 18,430 |
| `config/errorhandlers/` | 1 | 1 | 1,604 |
| `config/messages/` | 2 | 2 | 5,606 |
| `config/process/` | 2 | 2 | 29,294 |
| `config/routes/` | 6 | 6 | 30,849 |
| `config/validators/` | 2 | 2 | 6,436 |
| `css/` | 4 | 0 | 405,718 |
| `css/common/` | 1 | 0 | 19,904 |
| `css/fontawesome/` | 5 | 0 | 696,323 |
| `images/` | 2 | 0 | 10,362 |
| `images/admin/` | 5 | 0 | 9,907 |
| `images/datatable/` | 3 | 0 | 8,693 |
| `images/logos/` | 5 | 0 | 8,053 |
| `images/passphrase/` | 4 | 0 | 62,219 |
| `libs/` | 46 | 46 | 1,614,317 |
| `libs/codemirror/` | 4 | 4 | 355,901 |
| `locales/en/` | 3 | 0 | 68,657 |
| `org/forgerock/` | 303 | 303 | 1,311,214 |
| `partials/alerts/` | 1 | 0 | 620 |
| `partials/breadcrumb/` | 1 | 0 | 227 |
| `partials/form/` | 6 | 0 | 2,840 |
| `partials/headers/` | 2 | 0 | 1,172 |
| `partials/login/` | 13 | 0 | 4,266 |
| `partials/process/` | 1 | 0 | 1,893 |
| `partials/profile/` | 1 | 0 | 2,715 |
| `partials/providers/` | 1 | 0 | 217 |
| `partials/util/` | 3 | 0 | 538 |
| `store/` | 1 | 1 | 1,394 |
| `store/actions/` | 2 | 2 | 2,840 |
| `store/reducers/` | 3 | 3 | 4,627 |
| `templates/admin/` | 102 | 0 | 108,576 |
| `templates/common/` | 25 | 0 | 21,469 |
| `templates/openam/` | 12 | 0 | 12,414 |
| `templates/user/` | 59 | 0 | 60,054 |
| `themes/dark/` | 4 | 0 | 143,069 |

## 4. The bundle is partial — the fact that governs tasks 4.4–4.8

`requirejs:compile` runs with `include: ["main"]` and nothing else. It follows only the static
dependency graph reachable from `main.js`, which reaches **90 named module ids**. Everything
else in the application ships as an individual AMD file and is fetched by RequireJS at runtime.

| | Count |
|---|---:|
| Named `define("id",…)` inside `main.js` | 90 |
| …of those, also shipped as a standalone `.js` file (**double-shipped**) | 76 |
| …of those, present only inside the bundle (vendor `paths` aliases) | 14 |
| Shipped standalone `.js` files **not** in the bundle | 308 |
| Total `.js` files shipped | 384 |

308 + 76 = 384. The 14 bundle-only ids are vendor libraries reached through
`require.config.paths` — they ship under their real filenames in `libs/`, not under their alias:

`backbone`, `bootstrap`, `bootstrap-dialog`, `form2js`, `handlebars`, `i18next`, `jquery`, `js2form`, `lodash`, `moment`, `reactAutosizeInputDep`, `reactSelectDep`, `redux`, `spin`

### What this means for a Vite build

- A Vite build that emits one bundle plus hashed chunks does **not** reproduce this shape. The
  308 unbundled modules are addressed **by path at runtime**, and their paths are stable, unhashed
  and part of the deployed contract.
- `config/AppConfiguration.js` and `config/ThemeConfiguration.js` are `excludeShallow` in
  `requirejs:compile` — they are deliberately kept out of the bundle so the UI can be customised
  without repackaging. Both ship standalone and are absent from `main.js`. Confirmed:
  `grep -c 'define("config/AppConfiguration"' target/compiled/main.js` → `0`.
- `AppConfiguration.js` names modules **by string**, so the set of reachable module ids is not
  closed at build time (design.md D1/D5). Operators may also drop their own module into the
  deployed `/XUI` and have the loader reach it by id — `e2e/xui/xui-operator-module.spec.mjs`
  asserts exactly that.

## 5. Root files — the stable-path contract

| File | md5 | Bytes | Contract |
|---|---|---:|---|
| `favicon.ico` | `2983db6a524832a47322862487cb4bd0` | 15,086 | static |
| `index.html` | `e3444d65a0de8574ec3f356481f16e09` | 988 | `${version}` replaced with the Maven version; bootstraps RequireJS, **no `<script type="module">`** |
| `main-authorize.js` | `2d68e9cc4918e7c2625461ae1849921e` | 5,044 | **separate entry**, unhashed, loaded by path from AM's OAuth2 consent page |
| `main-device.js` | `8b90ee3a59609959db6110b8241be6cc` | 2,907 | **separate entry**, unhashed, loaded by path from AM's device flow pages |
| `main.js` | `2d6b6ce6644ba9ef4b2dbbaef37de2ae` | 543,480 | the r.js bundle; `<script>`-loaded via RequireJS `deps: ["main"]` |
| `main.js.map` | `36d56746c0a7ba001ce8890fb1711e7f` | 1,590,337 | source map for the bundle |
| `oauthReturn.html` | `aa8cab5e3b6880371fdca054d8cc8ddb` | 1,554 | static |
| `timezones.json` | `1c7df355ca50bcd4915fcb237b3f5d72` | 15,063 | static, fetched at runtime |

Three entry points — `main.js`, `main-authorize.js`, `main-device.js` — all at the tree root with
**stable, unhashed names**. Vite's default `assets/<name>-<hash>.js` breaks this.

## 6. Static assets that must be copied verbatim

**268 files.** None passes through Babel, r.js or LESS; `copy:compiled` moves them from the
composition directory unchanged, selected by `nonCompiledFiles`:

```js
nonCompiledFiles = [
    "**/*.html", "**/*.ico", "**/*.json", "**/*.png", "**/*.eot",
    "**/*.svg",  "**/*.woff", "**/*.woff2", "**/*.otf",
    "css/bootstrap-3.3.5-custom.css",
    "themes/**/*.*"
]
```

229 of them are `.html` Handlebars templates and partials **fetched at runtime by path**, not
imported. Nothing in the module graph references them, so no bundler discovers them; they have to
be copied. They are also the surface operators override on a deployed instance
(`e2e/xui/xui-theming.spec.mjs`), so their paths are part of the contract too.

## 7. Full per-file manifest

All 652 files, `md5  size  path`, sorted by path. Paths are relative to `target/compiled`
and identical to their paths inside `-www.zip` and under `/openam/XUI/`.

```
ef883b0abee35486168f43df26346e0e       2292  components/Block.js
2f213fafdc1228dfc8f329dca3f32fbe       1640  components/CallToAction.js
bc0be05ecd63f2c77eee68e5d1a777e4       2348  components/Card.js
b6e58b29508e68916e12be9bfefef392       1704  components/PageDescription.js
c093938fd1f33dc0dfc7f204a7cec62a       2240  components/SimplePageHeader.js
43a06b3bf39020c6ae502e23e4303adf       9328  config/AppConfiguration.js
f370e5f779ef7f8488c2e8f22ae8b569       3980  config/AppMessages.js
46a4c305733e427510b8e3b638fbd944       3752  config/ThemeConfiguration.js
ca95cd7fcbf190c5972f1ff11a43d856       1604  config/errorhandlers/CommonErrorHandlers.js
016911ff49c2d0d1b733982ebe4d4101       1370  config/main.js
39c6c1bea9c8807d1a167d477386a558       3003  config/messages/CommonMessages.js
6e3b8d8d434b414914f5a2a14f05c1bc       2603  config/messages/UserMessages.js
35fe511cc9049e92d0d10ae3afc515c5      11627  config/process/AMConfig.js
1ec8b788a8635ecb528edb206d063320      17667  config/process/CommonConfig.js
5685a33be0e7925b5babbc3c73b7883a       2731  config/routes/AMRoutesConfig.js
e2474098df010a160d86570625e66860       1866  config/routes/CommonRoutesConfig.js
576e0f8b399b7971640ffb76f5c5fcf3       1874  config/routes/UserRoutesConfig.js
8bcabc6b0443f37288b26811f6a62a98       5785  config/routes/admin/GlobalRoutes.js
65b1bb157b4f69a279b71829b2565ea1      13534  config/routes/admin/RealmsRoutes.js
d7fdfaf7748f9c478abcd02234a70e35       5059  config/routes/user/UMARoutes.js
f92f3403a9a96a7af7b8d7fed8dbbc24       3199  config/validators/AMValidators.js
161b52164467c9dbb2d78d6be12276b9       3237  config/validators/CommonValidators.js
957474c344c7131fb8e093449cc4893a     147430  css/bootstrap-3.3.5-custom.css
b53d9e9ab592f2def188d8178797e16d      19904  css/common/structure/config.json
87d8ca3ddc57e7d2da6226e480f90457     109688  css/fontawesome/fonts/FontAwesome.otf
32400f4e08932a94d8bfd2422702c446      70807  css/fontawesome/fonts/fontawesome-webfont.eot
f775f9cca88e21d45bebe185b27c0e5b     365616  css/fontawesome/fonts/fontawesome-webfont.svg
a35720c2fed2c7f043bc7e4ffb45e073      83588  css/fontawesome/fonts/fontawesome-webfont.woff
db812d8a70a4e88e888744c1c9a27e89      66624  css/fontawesome/fonts/fontawesome-webfont.woff2
7859690d4d01a822395378b8b43fe8b6      89221  css/structure.css
6ebeb312190424bb6f540a9cc2b39ab5     158377  css/styles-admin.css
30c3779152a174b221cd8bcf3e873853      10690  css/theme.css
2983db6a524832a47322862487cb4bd0      15086  favicon.ico
1c65524bbbcdc90afcc76d5e1b0f4366       1903  images/admin/auth-criteria/diagram-last.png
8106f46d7d1b46ba82b9f8f1ae3fb65f       1933  images/admin/auth-criteria/diagram-optional.png
e407b26094e31358b66de50b78779a88       2035  images/admin/auth-criteria/diagram-required.png
ead7698ee191005ccee3dfeeb12b85ba       1990  images/admin/auth-criteria/diagram-requisite.png
ec15a9cb9ea507d2b388586dec46fc5a       2046  images/admin/auth-criteria/diagram-sufficient.png
f3dd0212b70a4291ab8980412436a2a7       2840  images/datatable/sort_asc.png
085f334d21ad36b2db51b6a15d02344f       3014  images/datatable/sort_both.png
a9723f3e23faa0a25004e05c5d16f6bb       2839  images/datatable/sort_desc.png
8a762acb40bd747fc586694b9f3144ef       7882  images/login-logo.png
d24bd35ba40364149162b903a10f44bc       2480  images/logo-horizontal.png
0c0d6bba9a8908a532ec36eead0afa0c       1403  images/logos/facebook.png
12137dfa9b8974ad2d766d8a388a14ec       2380  images/logos/googleplus.png
5991370c7d42d9fcf2f01f4c17ab57a7       1936  images/logos/microsoft.png
89ed8cf4d0df1f54e7236546215927f7       1251  images/logos/salesforce.png
03b59a805e016ed4d2d69cd8e766dedf       1083  images/logos/zendesk.png
593ba280ac000582f860c1b7554beb7f       8827  images/passphrase/mail.png
c1c892bc05e26dc3af72bac7a4c56bf9      14576  images/passphrase/report.png
00961b64e280d828cb0b8647509ad73e      20263  images/passphrase/twitter.png
3f95c102b6396d41c08d037ca07f0429      18553  images/passphrase/user.png
e3444d65a0de8574ec3f356481f16e09        988  index.html
9c3e3189b75efd56066402f80c3e781b      19999  libs/backbone-1.1.2-min.js
2282dafb7fea1291a78fd389e5afeff9      25019  libs/backbone-relational-0.9.0-min.js
7ef9bd3e64b30585f714b9e386df6d75      10708  libs/backbone.paginator.min-2.0.2-min.js
af6fb96aa2e6519098358b9fbd2cd176      12136  libs/backgrid-filter.min-0.3.7-min.js
ebd4b6db83779dc4f5de4c60f113d92a       3915  libs/backgrid-paginator-0.3.5-custom.min.js
c08f46d1c64b6c6517264fb13e84312d       3815  libs/backgrid-paginator.min-0.3.5-min.js
9cefb2ccf039f56e4310b03a30bac1df       3357  libs/backgrid-select-all-0.3.5-min.js
248635b0bcc55409ee5976320f2e8ce8      25556  libs/backgrid.min-0.3.5-min.js
152e366267c0f3b89e9806d4c54d7212        835  libs/base64-1.0.0-min.js
8015042d0b4ac125867af5b096b175ce      68890  libs/bootstrap-3.3.5-custom.js
28af1dfd23b1a43c8094fb6440d18170      10783  libs/bootstrap-clockpicker-0.0.7-min.js
7b41840840e049f535337b89e889e042      35776  libs/bootstrap-datetimepicker-4.14.30-min.js
5ce8851dc823429a42ab6147554403cc      20132  libs/bootstrap-dialog-1.34.4-min.js
7c4081d595b8b82b13ed88285670fd0e       5105  libs/bootstrap-tabdrop-1.0.js
757d3f1f159fa90976d88e6d6120cb68       1102  libs/classnames-2.2.5.js
fb86184c4fb36398188f2199fd28f167       1494  libs/codemirror/addon/display/fullscreen.js
1c570cd14e3ec3db7726f86bfbabf2d3     320636  libs/codemirror/lib/codemirror.js
4f97d9e79258b2a380fcda2daf85afd6       7625  libs/codemirror/mode/groovy/groovy.js
921ad047a5a73a57f2ccf5d526faf01c      26146  libs/codemirror/mode/javascript/javascript.js
8ef652fe9e78af44f287ac3c92d4a07f      11368  libs/dragula-3.6.7-min.js
897ec696be559d5bb804b0803616efc5      10160  libs/form2js-2.0-769718a.js
5a252786c5496da621127ef52e37d5cb      80257  libs/handlebars-4.7.7-min.js
c4d39d28c89d97c1c510b03067015f84     179306  libs/handlebars-4.7.7.js
35578b3a6b9c4592c52b742017d3ffd2      32398  libs/i18next-1.7.3-min.js
2c872dbe60f4ba70fb85356113d8b35e      87533  libs/jquery-3.7.1-min.js
8efebfc0877c405bbd840a9f5b40625a      23858  libs/jquery-sortable-0.9.13.js
fa5163385cd7d168fd1049c63c17618c       1503  libs/jquery.autosize.input.min.js
f10a418e5706963ae4b98710b25b44a8       1065  libs/jquery.ba-dotimeout-1.0-min.js
d7098f9b5df7c2fdf5119c7428a19441       5297  libs/jquery.placeholder-2.0.8.js
fc83dc6af4259d45638391faa8fc9b29       9118  libs/js2form-2.0-769718a.js
6c39c8bed909bd51e01236c0f6dfa83f     138961  libs/jsoneditor-0.7.23-custom.js
ce6de91cfa8e25ec3b9f27e5c6f6884c     125002  libs/jsoneditor-0.7.9-min.js
7629cac4f079926ef505e2271bb5135f      50543  libs/lodash-3.10.1-min.js
8c6cdcd56adaebdac8ffbb99c395c91e       3335  libs/microplugin-0.0.3.js
bb51b2cdde2dec6ee91604f77df6cf75      58887  libs/moment-2.28.0-min.js
e92d40fd03fb45a4f3fcdd73fba4894f       3668  libs/popover-clickaway.js
e259e455fb7a06ebf1b26990029a9ce8      20387  libs/qrcode-1.4.4-min.js
a4137323c75e65beca5a3ca602d78a87     147398  libs/react-15.2.1-min.js
bf1e00b835f873453651bb9e721787e5     183560  libs/react-bootstrap-0.30.1-min.js
981fd81aa9e74564eadc59331f03e23c        709  libs/react-dom-15.2.1-min.js
c60e2a133dcf42fdde9c67f85b8e94d9       3708  libs/react-input-autosize-1.1.0-min.js
bd4ca8e8d9c8e0317b25b85165f341fb      45790  libs/react-select-1.0.0-rc.2-min.js
c5ee165e10f61394f51c179ca0617801       6733  libs/redux-3.5.2-min.js
01252f25e96768861bd3effa7bf8889e      17420  libs/requirejs-2.3.7-min.js
7a8aec7b45f095debbdd50703b06e6c3      37122  libs/selectize-0.12.1-min.js
7a8aec7b45f095debbdd50703b06e6c3      37122  libs/selectize-non-standalone-0.12.1-min.js
3e0fa9856cfb48429c11c8363a197736       4711  libs/sifter-0.4.1-min.js
104d92cec8a995e6ee3fcde85dce4832       4121  libs/spin-2.0.1-min.js
2a17da82e4461058b86947ca4dc76342      16259  libs/text-2.0.15.js
68f8cdcac085adbaf0a5e8271e6f66a4      19890  libs/xdate-0.8-min.js
cffb234acd0779c058337b1b141fc798        535  locales/en/authorize.json
df77525d23e3d2c6bff1d6101fd14791        437  locales/en/device.json
e85549b58870c293ca01bc042affa39a      67685  locales/en/translation.json
2d68e9cc4918e7c2625461ae1849921e       5044  main-authorize.js
8b90ee3a59609959db6110b8241be6cc       2907  main-device.js
2d6b6ce6644ba9ef4b2dbbaef37de2ae     543480  main.js
36d56746c0a7ba001ce8890fb1711e7f    1590337  main.js.map
aa8cab5e3b6880371fdca054d8cc8ddb       1554  oauthReturn.html
f74f00a7baa50b67b6cd092f50750d47       1305  org/forgerock/commons/ui/common/EnableCookiesView.js
fbc8ae2f61fffbd208f1c970b25e0bc4       3373  org/forgerock/commons/ui/common/LoginDialog.js
5d018bae6758e8605d90708b61599627       2853  org/forgerock/commons/ui/common/LoginView.js
075023d574cbcbe7f5f31738022107ad       1040  org/forgerock/commons/ui/common/NotFoundView.js
44e6aac05ceebd7783d3da5fa4013a74       3605  org/forgerock/commons/ui/common/SiteConfigurator.js
b0afadb9d1f970ef1f31284127bbfe6a       1424  org/forgerock/commons/ui/common/UnauthorizedView.js
49624ad5ea845803688049f0326ddda7       2055  org/forgerock/commons/ui/common/backgrid/Backgrid.js
bc2aab566fffa6fcb47ce68820f39450       2511  org/forgerock/commons/ui/common/backgrid/extension/ThemeablePaginator.js
67521712667726f6dfd9712340e3d61c       1994  org/forgerock/commons/ui/common/backgrid/extension/ThemeableSelectAllCell.js
f41cd34f4c5c3d7b605cf95283d3a80d       3011  org/forgerock/commons/ui/common/backgrid/extension/ThemeableServerSideFilter.js
57c149601544be1795db68a5ca19061d       2562  org/forgerock/commons/ui/common/components/BootstrapDialog.js
35c5950569cdbf5319fe2c8fb50147df       3369  org/forgerock/commons/ui/common/components/BootstrapDialogView.js
14ea01564dc74fa424f78a3ebeb5343b       3269  org/forgerock/commons/ui/common/components/Breadcrumbs.js
8eb683c7b19e35cfe64b5a91376ef07d       6603  org/forgerock/commons/ui/common/components/ChangesPending.js
077504feb8f513bc784497b1760497d7       1645  org/forgerock/commons/ui/common/components/ConfirmationDialog.js
2610906e93f886de83016f039dd9e669       3655  org/forgerock/commons/ui/common/components/Dialog.js
da8b7bd4027605e1dc4e75e24487ccb8       1840  org/forgerock/commons/ui/common/components/Footer.js
86f981a242f5ee121c415358bcbf9a10       1050  org/forgerock/commons/ui/common/components/LoginHeader.js
a00fcd42b07ba3eb44989b25ae4e198b       5550  org/forgerock/commons/ui/common/components/Messages.js
e7e7b6b62b4b367572267755f2a43ade      14763  org/forgerock/commons/ui/common/components/Navigation.js
92a422639fcc55defd61718402d6ae01       3002  org/forgerock/commons/ui/common/components/hoc/withRouter.js
80d153e5f9512b686acedb991e29f50c       1316  org/forgerock/commons/ui/common/components/hoc/withRouterPropType.js
85351d23565229e24939538e57afbec6       1567  org/forgerock/commons/ui/common/components/navigation/filters/RoleFilter.js
4caca56a9773c286f175e4e543b9f4f2       1137  org/forgerock/commons/ui/common/components/popup/PopupCtrl.js
7a453c00b2d50f4282698250aa6ebac9       1550  org/forgerock/commons/ui/common/components/popup/PopupView.js
03eb29d63ebc37f08f5c65d4e111a62d       1363  org/forgerock/commons/ui/common/main.js
5fe8efa405bf923f5e675c2c622c9480       8200  org/forgerock/commons/ui/common/main/AbstractCollection.js
15260fffc2eb11160d44bab770f84fa7       2182  org/forgerock/commons/ui/common/main/AbstractConfigurationAware.js
b8f18c0d9b143b6a0a59397cc5bacd56       7163  org/forgerock/commons/ui/common/main/AbstractDelegate.js
36712b6253a5faa0bdd87a8567df37f6       5221  org/forgerock/commons/ui/common/main/AbstractModel.js
3379bf1c61d3bbaf1b3055fffce7ffc0       8105  org/forgerock/commons/ui/common/main/AbstractView.js
8ca2a87f4ca52a9f5c78b4e2a7f77ee5       3012  org/forgerock/commons/ui/common/main/Configuration.js
38e84e46bf18d5cf979537586257edcf       3701  org/forgerock/commons/ui/common/main/ErrorsHandler.js
e594964f7a3db5f7ec993dc09b3cfe7e       2300  org/forgerock/commons/ui/common/main/EventManager.js
26b4ba7a5240c4b4294c6ba5bbbd3570       3695  org/forgerock/commons/ui/common/main/ProcessConfiguration.js
936f4c5a07fd134578bb29731d4d350f       2611  org/forgerock/commons/ui/common/main/ReactAdapterView.js
ac9710a1c64df9531ff2075f7cb88f5f       9153  org/forgerock/commons/ui/common/main/Router.js
8680d27ff6b3fea65c19898696c2363a       7654  org/forgerock/commons/ui/common/main/ServiceInvoker.js
0c7fad249c69fbdb7bfee888073ed803       2207  org/forgerock/commons/ui/common/main/SessionManager.js
d325fd607f050c3c7bb63f5e75e0efab       1516  org/forgerock/commons/ui/common/main/SpinnerManager.js
2ee1ee340cd10813497c58b927a84871       7186  org/forgerock/commons/ui/common/main/ValidatorsManager.js
f85aa19b6fa7b24c2e219b57579fed21       4233  org/forgerock/commons/ui/common/main/ViewManager.js
1ba98d931a7f40e4c4ea59723306ddfa       5338  org/forgerock/commons/ui/common/main/i18nManager.js
912e6d2782ab2a24b9aee1f9122733dd       2238  org/forgerock/commons/ui/common/util/AutoScroll.js
59b8ef9c3a2394965bf2a28d8853f7e0      14591  org/forgerock/commons/ui/common/util/BackgridUtils.js
4ddb7672d35d80d157c9a1916c582f53       3696  org/forgerock/commons/ui/common/util/Base64.js
476c661b4440ccfbf42afef1aaf47a3c       5343  org/forgerock/commons/ui/common/util/Constants.js
754e1cf003bef902ccd9939d6880e0dd       4233  org/forgerock/commons/ui/common/util/CookieHelper.js
7ab72c6a9e0024deab0245d929298eec       2374  org/forgerock/commons/ui/common/util/CustomPolyfill.js
daff56390f1b1dca405339d5dc11f60e       2683  org/forgerock/commons/ui/common/util/DateUtil.js
6c8cd519f7cb1499f7e871b1a87db53e      11561  org/forgerock/commons/ui/common/util/FormGenerationUtils.js
e4a4f5903301e7692a2ab274ef0f463f       1358  org/forgerock/commons/ui/common/util/Mime.js
a488e989d19855de901dae52e9b5e0aa       3747  org/forgerock/commons/ui/common/util/ModuleLoader.js
5b3d08df153a456cec1ebfe4b5bc1352       3117  org/forgerock/commons/ui/common/util/OAuth.js
3a6a1dc450c570a1d2d791f50d46d12f      10853  org/forgerock/commons/ui/common/util/ObjectUtil.js
121731fa56f49bc5f2124ae7ca9b9ad2       1991  org/forgerock/commons/ui/common/util/Queue.js
05431574e8805d4c54d802cdb180cf8d      20218  org/forgerock/commons/ui/common/util/UIUtils.js
e90b04aeff9a350918c39b1fd488bda1       4222  org/forgerock/commons/ui/common/util/URIUtils.js
5c222292a515e95df6bebed0af334a19       2712  org/forgerock/commons/ui/common/util/ValidatorsUtils.js
7e7490b0dcb7b32dc90c5a96c7b5f464       1367  org/forgerock/commons/ui/common/util/reactify.js
0768bce614ad737a25891e291a276ab3      10195  org/forgerock/commons/ui/user/anonymousProcess/AnonymousProcessView.js
4faddcca6ed25ed2f2e0039deb96fc04       1055  org/forgerock/commons/ui/user/anonymousProcess/ForgotUsernameView.js
ad4f023821e2e5aa566a0300819fae48       4393  org/forgerock/commons/ui/user/anonymousProcess/KBAQuestionView.js
ee560ed1b0ca42c3952c630183eca2b0       5249  org/forgerock/commons/ui/user/anonymousProcess/KBAView.js
b1cdda64244bcf599f426ef6e30dbace       1049  org/forgerock/commons/ui/user/anonymousProcess/PasswordResetView.js
614cb3f3c98dcdc8b08fddcdf1b35b7d       1793  org/forgerock/commons/ui/user/anonymousProcess/SelfRegistrationView.js
8f4a538113a7c79cac1064b48f8786d7       2862  org/forgerock/commons/ui/user/delegates/AnonymousProcessDelegate.js
3a3aa3e614c72b492f914bf4da1dbeb2       1904  org/forgerock/commons/ui/user/delegates/KBADelegate.js
52c65f6789369a80b24294ef28ee1de0       6370  org/forgerock/commons/ui/user/profile/AbstractUserProfileTab.js
e02092aeac73618a14a08580e96a64a7       2777  org/forgerock/commons/ui/user/profile/ConfirmPasswordDialog.js
ff4cc8d0006e4e2f1a25365596cdc75f       9675  org/forgerock/commons/ui/user/profile/UserProfileKBATab.js
56712bef5434a167505ca990ec58a149       5016  org/forgerock/commons/ui/user/profile/UserProfileView.js
c4cf0716c3aaf54b9718378ddd3ea952       2146  org/forgerock/openam/server/util/QRCodeReader.js
47231b834ba12f8f15636083a3e9de00       3073  org/forgerock/openam/ui/admin/main.js
7b587362fafdd497e0149682943933af       3607  org/forgerock/openam/ui/admin/models/Form.js
acb379f16f6e0ef1e6751b8d7f02325c       1241  org/forgerock/openam/ui/admin/models/FormCollection.js
ab57e8c08b9b66b334dae547a3dd420a       2127  org/forgerock/openam/ui/admin/models/authorization/PolicyModel.js
b6cdcf2732fe78501fc9d0ac167765fd       2399  org/forgerock/openam/ui/admin/models/authorization/PolicySetModel.js
8cd85f9465dbd5aace56693447037a15       2219  org/forgerock/openam/ui/admin/models/authorization/ResourceTypeModel.js
4ec6c4513680f6b726a9e7f8df5402c6       2290  org/forgerock/openam/ui/admin/models/scripts/ScriptModel.js
e520454dc15d70deb15803dc6dd4362d       6114  org/forgerock/openam/ui/admin/services/SMSServiceUtils.js
b1cb46d65687417f5892bcc8f2443f21       2164  org/forgerock/openam/ui/admin/services/global/ApiService.js
f5433ded44ec2f436a0195ccf5d9cdd5       4011  org/forgerock/openam/ui/admin/services/global/AuthenticationService.js
d0a05959af13b5b6b3f6193ff5e39c7e       5102  org/forgerock/openam/ui/admin/services/global/RealmsService.js
fe5b4d890242b54b18c7480a684e94c2       3591  org/forgerock/openam/ui/admin/services/global/ScriptsService.js
279fcdaab3a329ec6a503baec1bb77b7       8164  org/forgerock/openam/ui/admin/services/global/ServersService.js
adfc2a7a26d844c8441b012e6102cba7      14220  org/forgerock/openam/ui/admin/services/global/ServicesService.js
e8d889067fbc5dd65c279a2d4e398d8e       2573  org/forgerock/openam/ui/admin/services/global/SessionsService.js
ff8dffe7424a922d89e8d25b6e85bf39       4948  org/forgerock/openam/ui/admin/services/global/SitesService.js
a701c769ed4008aaa555a548956649ad       1980  org/forgerock/openam/ui/admin/services/global/UsersService.js
33b60923a903751f26ae44aa9209bd87       3773  org/forgerock/openam/ui/admin/services/realm/AgentsService.js
e773cd743f33f885028a263b8ba2017b       9993  org/forgerock/openam/ui/admin/services/realm/AuthenticationService.js
99e707fc111c390fff19ab024b449a64       1532  org/forgerock/openam/ui/admin/services/realm/DashboardService.js
1865f150577db74bda68d3003d614d1a       5206  org/forgerock/openam/ui/admin/services/realm/PoliciesService.js
edb5ce5bafccfc7333c3afd6e2420fa2       1734  org/forgerock/openam/ui/admin/services/realm/ScriptsService.js
6104e2f5f1a612af139659725c7fd737      10404  org/forgerock/openam/ui/admin/services/realm/ServicesService.js
a27381dd5b7c659bb6527f72327785ca       1174  org/forgerock/openam/ui/admin/utils/AdministeredRealmsHelper.js
5f834c740e608daecbd76fa1ba23e17c       2065  org/forgerock/openam/ui/admin/utils/FormHelper.js
ad7539f1f284bc0cc9d9879794dc9bc4      13155  org/forgerock/openam/ui/admin/utils/JSONEditorTheme.js
45387998fa007b749336b7d0902733cd       1758  org/forgerock/openam/ui/admin/utils/ModelUtils.js
04677ebe54a4cc6e067e8e5ffa970649       4571  org/forgerock/openam/ui/admin/utils/RedirectToLegacyConsole.js
69e131b3fa7380e62ada0d0c6e53738a       1035  org/forgerock/openam/ui/admin/utils/deprecatedWarning.js
28c0ddf570565735a10512210ff2ed99       2651  org/forgerock/openam/ui/admin/utils/form/bindSavePromiseToElement.js
9a10fad0247c7c9b099bda9cee7fd071       1266  org/forgerock/openam/ui/admin/utils/form/setActiveTab.js
9a33a37b8f3074780bed30e19c23e5bd       2600  org/forgerock/openam/ui/admin/utils/form/showConfirmationBeforeAction.js
ae2573b30310eb6b49f1a597d776a6a8       1345  org/forgerock/openam/ui/admin/views/api/ApiDocView.js
e0da67fd20dd982d76279b16eb4bb1af       1345  org/forgerock/openam/ui/admin/views/api/ApiExplorerView.js
313b0f52afe8ca3daa63fe560fdde0dd       7470  org/forgerock/openam/ui/admin/views/api/ListApiView.js
b6f5551b2ccb3dafecf2510246455504       2714  org/forgerock/openam/ui/admin/views/api/SideNavChildItem.js
b9cf3c5aec060da5e5ef9528aa8a355f       3366  org/forgerock/openam/ui/admin/views/api/SideNavGroupItem.js
52c8699ccacafae38ad503417c97c504       2073  org/forgerock/openam/ui/admin/views/common/Backlink.js
95d4828a55d1e1f21bc84bb9a43cdcec       3643  org/forgerock/openam/ui/admin/views/common/TabSearch.js
5f6dbda4272c3dcefd2e8d5b981e932a       1844  org/forgerock/openam/ui/admin/views/common/ToggleCardListView.js
93ef75c026d5e3ad3bddaa2d5a178a08       4092  org/forgerock/openam/ui/admin/views/common/navigation/createBreadcrumbs.js
53b646a236907422e6dba9551ea2e506       3473  org/forgerock/openam/ui/admin/views/common/navigation/createTreeNavigation.js
29eb8a5e502a0e5b96f177645dda9166      10808  org/forgerock/openam/ui/admin/views/common/schema/EditSchemaComponent.js
941349ca459feefe7017508be51061e7       3921  org/forgerock/openam/ui/admin/views/common/schema/NewSchemaComponent.js
6ad731b6b976855ce17c2b028b366457       3449  org/forgerock/openam/ui/admin/views/common/schema/SubSchemaListComponent.js
bef7542d6f294ff19cb2e8adafb92406       9607  org/forgerock/openam/ui/admin/views/common/server/EditServerView.js
e7a0fbf8165e8c4ce7d963a373d4c08b       3725  org/forgerock/openam/ui/admin/views/configuration/authentication/EditGlobalAuthenticationView.js
c481b476097e150b19c15ecd5bd7b6ba       7494  org/forgerock/openam/ui/admin/views/configuration/authentication/ListAuthenticationView.js
fb41b0dda65b9537032f081e2d743e92       5372  org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceSubSchemaView.js
df9b0c785eaab8c0041116d21f190e23       4226  org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceSubSubSchemaView.js
e6a3cd7f5d4e6eaf45794916b56ab26f       4486  org/forgerock/openam/ui/admin/views/configuration/global/EditGlobalServiceView.js
f5b996d51d4842703ebd9246053876d2       6585  org/forgerock/openam/ui/admin/views/configuration/global/ListGlobalServicesView.js
981e318c96577fab2c5489e8b5230aa9       4298  org/forgerock/openam/ui/admin/views/configuration/global/NewGlobalServiceSubSchemaView.js
40d831f6c2794f48880ff6e4193a6e07       6034  org/forgerock/openam/ui/admin/views/configuration/global/scripting/ScriptsList.js
615ff531c828004f57b63078eeea9a42       2341  org/forgerock/openam/ui/admin/views/configuration/server/EditServerDefaultsTreeNavigationView.js
de4b5b7d3dad160a98b54d15401f5ef0       2739  org/forgerock/openam/ui/admin/views/deployment/servers/EditServerTreeNavigationView.js
1264f39b416c45749ff06d2ebf9f791f       4209  org/forgerock/openam/ui/admin/views/deployment/servers/ListServersView.js
6048de835f9683dc6878d2c2542f7eb8       4747  org/forgerock/openam/ui/admin/views/deployment/servers/NewServerView.js
25d630ef70794439f4e4a1dbec99f9b0       3894  org/forgerock/openam/ui/admin/views/deployment/sites/EditSiteView.js
558373e162ec82ad5694cec68c50e019       4251  org/forgerock/openam/ui/admin/views/deployment/sites/ListSitesView.js
25b9156935fb4e84dd73da01416193be       2874  org/forgerock/openam/ui/admin/views/deployment/sites/NewSiteView.js
1a944838c6935f6975e0ceab9c9fc2c1       9832  org/forgerock/openam/ui/admin/views/realms/EditRealmView.js
ae62a3194872e2474a7d75350769aaf2      11930  org/forgerock/openam/ui/admin/views/realms/ListRealmsView.js
3d10f80b85fb298ca78fad43c6c0686d       5732  org/forgerock/openam/ui/admin/views/realms/RealmTreeNavigationView.js
9130230541ef53180967e7f79a7069f8       7869  org/forgerock/openam/ui/admin/views/realms/applications/agents/NewAgentView.js
3942496ca33627bb25a6028da116882a       8049  org/forgerock/openam/ui/admin/views/realms/applications/agents/SelectAgentView.js
6c6bdbd52a9e371d8eedba2a0b06d68d       5511  org/forgerock/openam/ui/admin/views/realms/authentication/ChainsView.js
187a58170e4631acaf0352a72252039b       1668  org/forgerock/openam/ui/admin/views/realms/authentication/EditModuleDialog.js
002b05779a436ea207d1201830e7cbbd       6336  org/forgerock/openam/ui/admin/views/realms/authentication/ModulesView.js
6242f171d002c7d56d55afb724ab42af       3390  org/forgerock/openam/ui/admin/views/realms/authentication/SettingsView.js
b3b8578ce9927eee8bfec23d294d3fcf       3060  org/forgerock/openam/ui/admin/views/realms/authentication/chains/AddChainView.js
119e54eb0baae98f5b1c081725e890eb      11249  org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditChainView.js
083bc112426cf60698cee0d773c70c9f       7104  org/forgerock/openam/ui/admin/views/realms/authentication/chains/EditLinkView.js
2bfb2426f0f04ea9b532a643fc0d47b0       4670  org/forgerock/openam/ui/admin/views/realms/authentication/chains/LinkView.js
f241c96ef68938a7984304eb0b633cd9       3776  org/forgerock/openam/ui/admin/views/realms/authentication/chains/PostProcessView.js
77c0338fd6cdd955d70ac5dbe8d20cf9       4317  org/forgerock/openam/ui/admin/views/realms/authentication/modules/AddModuleView.js
c58485e225149bfc76a2146d02e231b9       9657  org/forgerock/openam/ui/admin/views/realms/authentication/modules/EditModuleView.js
42ee2066c08464fde85601eb685df950       2780  org/forgerock/openam/ui/admin/views/realms/authorization/common/AbstractListView.js
a62cf8f2176077a60b4cbfbcfc199fa2       3876  org/forgerock/openam/ui/admin/views/realms/authorization/common/StripedListEditingView.js
c36c0783e7c11ea0d2edc4c93f0ed59e       3990  org/forgerock/openam/ui/admin/views/realms/authorization/common/StripedListView.js
1b058524eaebe050df040e3aa9c7000c       5817  org/forgerock/openam/ui/admin/views/realms/authorization/policies/CreatedResourcesView.js
6cd41f90b06951b86ac657fcf4dced8c      12876  org/forgerock/openam/ui/admin/views/realms/authorization/policies/EditPolicyView.js
b2997e95f5f820683bd98815ace671bd       6591  org/forgerock/openam/ui/admin/views/realms/authorization/policies/PoliciesView.js
89e93f87d80fbc0718aff59d9c2a78b5       4953  org/forgerock/openam/ui/admin/views/realms/authorization/policies/PolicyActionsView.js
be725e373553f073860c7f8f6986f945       1443  org/forgerock/openam/ui/admin/views/realms/authorization/policies/attributes/CustomResponseAttributesView.js
fcaf3d90c52e6e8a2b914603cb5e4f76       2077  org/forgerock/openam/ui/admin/views/realms/authorization/policies/attributes/StaticResponseAttributesView.js
9e7a5478e67ab98f307d97a4116c6f3d       2675  org/forgerock/openam/ui/admin/views/realms/authorization/policies/attributes/SubjectResponseAttributesView.js
7c48d62f8f8c87661a25293b38893054       7587  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrArrayView.js
025c8b0d24b272663f1007cbdb4fef20       3260  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrBaseView.js
b0611bc9bea435133665b1a28fc945af       2155  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrBooleanView.js
18e769f2bf9b831dc9aec5b255127833       2044  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrDateView.js
d6a3ac5eb3cb81c617a771a5cb7599ae       2012  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrDayView.js
593df1f48e0e75a7d9ab634b5d85ac39       1325  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrEnumView.js
2dca0354326f0564bdb2a2e17e2aedba       3100  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrObjectView.js
ef3b97e5e7156aba907aaa91a0758ebd       2350  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrStringView.js
00c84e7882d7577d9f0900381d580888       1933  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ConditionAttrTimeView.js
68a1f57a327c6b3a23cb60b14708092a      13882  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/EditEnvironmentView.js
3e3cfd85d309873e643edc7b2ce92e78       9311  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/EditSubjectView.js
459ad0c0190edb6288d4f38b36a3c6e6       1560  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/LegacyListItemView.js
0df2022846e3b97a0f55a6cbbe49cb7c       3765  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageEnvironmentsView.js
d95c44132ea52cdd5279a01be249c0ae      17296  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageRulesView.js
b7e3456bbd483a116e6a59692df67493       3727  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/ManageSubjectsView.js
fbc85f2ff91ea50abad9cd3f202d77e4       3767  org/forgerock/openam/ui/admin/views/realms/authorization/policies/conditions/OperatorRulesView.js
0da9cd3e27f1582901cf4d61c89fc8e2      10019  org/forgerock/openam/ui/admin/views/realms/authorization/policySets/EditPolicySetView.js
87d29f7e2385d6066ff88ded864437d9       8843  org/forgerock/openam/ui/admin/views/realms/authorization/policySets/PolicySetsView.js
00e37d121f3b312b33d3aee074f89199       7813  org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/EditResourceTypeView.js
c5940e5cea24819b125c557b3b29ecce       4795  org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/ResourceTypeActionsView.js
6d2c8e711f4f11e62c0ead2178b9a3b7       2253  org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/ResourceTypePatternsView.js
7c3610298b4aa27d70d4340e3eb0d01b       6329  org/forgerock/openam/ui/admin/views/realms/authorization/resourceTypes/ResourceTypesView.js
2334082a3faeaf66b78d25fff08f2507       2135  org/forgerock/openam/ui/admin/views/realms/dashboard/DashboardTasksView.js
7c4e57daf5a5eca1e73410a00c52d707       2439  org/forgerock/openam/ui/admin/views/realms/dashboard/DashboardView.js
a225f2911c61a8f810156c8787b12ec0      17518  org/forgerock/openam/ui/admin/views/realms/scripts/EditScriptView.js
bd2103bbb8b8b90797694e838beea3a7       8556  org/forgerock/openam/ui/admin/views/realms/scripts/ScriptsView.js
f332815e348cc4e1e9dab498f768d97a       4257  org/forgerock/openam/ui/admin/views/realms/services/EditServiceSubSchemaView.js
f999a10276d34e696d96b196ee198063       4580  org/forgerock/openam/ui/admin/views/realms/services/EditServiceView.js
b0ad1e386db7a1f023bf2db5e1110f23       4107  org/forgerock/openam/ui/admin/views/realms/services/NewServiceSubSchemaView.js
f77b5645606cb140be02715ce20910e3       8666  org/forgerock/openam/ui/admin/views/realms/services/NewServiceView.js
856daa6ee81ec88778d1193fadd4a522       4594  org/forgerock/openam/ui/admin/views/realms/services/ServicesView.js
b1a17bd13aaacc7e4ec6a2bdad4d7cc1       3285  org/forgerock/openam/ui/admin/views/realms/services/SubSchemaListView.js
91578afbde0d6d6bb226042cba9d0861      10347  org/forgerock/openam/ui/admin/views/realms/sessions/SessionsTable.js
1171dd4a6c6ec6370aa29169102423bb       5235  org/forgerock/openam/ui/admin/views/realms/sessions/SessionsTableRow.js
f057e4d65cdcc1a00052a348ffa6bcfc      10738  org/forgerock/openam/ui/admin/views/realms/sessions/SessionsView.js
22bb28964cae4b0f62ce11282ccb8324       2551  org/forgerock/openam/ui/common/RouteTo.js
33bef76d3de60edaeea0c6e6a0d39641        905  org/forgerock/openam/ui/common/SingleRouteRouter.js
56ac7594f1925c84e6832e1d8ffbca66       1363  org/forgerock/openam/ui/common/components/Footer.js
6bf499f556e36c89e3e7587a102bcc07       1700  org/forgerock/openam/ui/common/components/PanelComponent.js
44398dc19b0bb66dad7e662a60e3f7d2       1323  org/forgerock/openam/ui/common/components/PartialBasedView.js
15abbbd668e4d3fd73f1b5d3813d47c1       8518  org/forgerock/openam/ui/common/components/SelectComponent.js
fc25b739b2494167ef98e79ea3c29a34       3702  org/forgerock/openam/ui/common/components/TabComponent.js
cfadb7ca16f9ecbfa67e9c63b989a278       1614  org/forgerock/openam/ui/common/components/TemplateBasedView.js
31275deb6dbe828789b096feea528592       5060  org/forgerock/openam/ui/common/components/TemplateComponent.js
9edeeadde18217f4b4e3c6281d970625       4224  org/forgerock/openam/ui/common/components/TreeNavigation.js
9d6299cbcff6b32305245232da4a2121       1173  org/forgerock/openam/ui/common/components/navigation/filters/RouteNavGroupFilter.js
486ae4505c18e98a59f48faea78e798f       6107  org/forgerock/openam/ui/common/components/table/InlineEditRow.js
65943bc1b8fa951ccbb830d0f63615b1       4665  org/forgerock/openam/ui/common/components/table/InlineEditTable.js
7ec6c64d920599321ad190129ebc215a        892  org/forgerock/openam/ui/common/main.js
9766132dd554c57c56053da37b5825ef      13298  org/forgerock/openam/ui/common/models/JSONSchema.js
086008881d1cfe19b5f564c3b29a9455       9783  org/forgerock/openam/ui/common/models/JSONValues.js
a7c252fd9992a7e96d28358d027423e3       3119  org/forgerock/openam/ui/common/models/cleanJSONSchema.js
7e4ac199b3153cd38b3b063869a93e41       1088  org/forgerock/openam/ui/common/models/schemaTransforms/transformBooleanTypeToCheckboxFormat.js
ec189ef523b218b516a417e8d0c20348       1034  org/forgerock/openam/ui/common/models/schemaTransforms/transformEnumTypeToString.js
c04222f62d059dbb3d012edc65bb62b5       1439  org/forgerock/openam/ui/common/models/schemaTransforms/warnOnInferredPasswordWithoutFormat.js
124d8a39c92d79354982073e57c1c40d       3120  org/forgerock/openam/ui/common/services/ServerService.js
5944ea424db3d296b212efc8c3541775       2872  org/forgerock/openam/ui/common/services/SiteConfigurationService.js
5e50e4ee1d0310f6fadbe6f54e254869       3881  org/forgerock/openam/ui/common/services/fetchUrl.js
a2cb5ecb89584ef2bda9d99a8e232596       2868  org/forgerock/openam/ui/common/sessions/SessionValidator.js
07abf0a660e7d28a872c51910fe88275       1666  org/forgerock/openam/ui/common/sessions/strategies/MaxIdleTimeLeftStrategy.js
447c82e52760af321d04329c1e892a84      10902  org/forgerock/openam/ui/common/util/BackgridUtils.js
fb0da6e30f461a2449d7c3f065627c64       4154  org/forgerock/openam/ui/common/util/Constants.js
c656d991d8631f62a5788b440e6fd657       1325  org/forgerock/openam/ui/common/util/ExternalLinks.js
bbb188bc39098bdbba5354adbc5bec79       1763  org/forgerock/openam/ui/common/util/Helpers.js
b73f48f61ca7aacfa66fb486852b452f       4030  org/forgerock/openam/ui/common/util/NavigationHelper.js
14d40f7f4731a2b344f0a5aab71a23df       3018  org/forgerock/openam/ui/common/util/Promise.js
61b862b66f30f08363575ff97cc77e9c       5698  org/forgerock/openam/ui/common/util/RealmHelper.js
0000b4c980ab71ac98db3d72c7ee1129       7573  org/forgerock/openam/ui/common/util/ThemeManager.js
dc9cd210ae73c78c4847f24fe7da8810       1586  org/forgerock/openam/ui/common/util/URLHelper.js
d9a31ccf88808eb5f31c95ebbd5b8c4d       1199  org/forgerock/openam/ui/common/util/array/arrayify.js
17b6ea4ff01937a22311a907c82a04c9       1325  org/forgerock/openam/ui/common/util/es6/normaliseModule.js
93c8afa793ef61199d16bd5260e05508       1419  org/forgerock/openam/ui/common/util/isRealmChanged.js
cf1298b315602bef3e84800f03ef469e       1110  org/forgerock/openam/ui/common/util/object/flattenValues.js
0fdfb744de8e6f80df0ca811177cecbb       2729  org/forgerock/openam/ui/common/util/uri/query.js
5af0501d36619f3c1d938864b96bd092       1253  org/forgerock/openam/ui/common/views/error/ForbiddenView.js
08966f637b85d954e9844f5cdcab384d       4128  org/forgerock/openam/ui/common/views/jsonSchema/FlatJSONSchemaView.js
7dc97544ab498d0a67da43885e3a2c3c       5941  org/forgerock/openam/ui/common/views/jsonSchema/GroupedJSONSchemaView.js
84a57f0e29aaf855337b636095d9fbfe       5576  org/forgerock/openam/ui/common/views/jsonSchema/editors/JSONEditorView.js
cd203b06ebc3e67ebefe10954cbc7433       3581  org/forgerock/openam/ui/common/views/jsonSchema/editors/TogglableJSONEditorView.js
ae95af67ecf8a3895b4889b7e5693474       1270  org/forgerock/openam/ui/common/views/jsonSchema/iteratees/createJSONEditorView.js
081714aa51d6b8706069f8bf81c4ecd2       1004  org/forgerock/openam/ui/common/views/jsonSchema/iteratees/emptyProperties.js
f3dc7e4d062926bd76607eb2f875cc6e       1317  org/forgerock/openam/ui/common/views/jsonSchema/iteratees/setDefaultPropertiesToRequiredAndEmpty.js
f6ebc051cb71a08d4725166566e758c3       1330  org/forgerock/openam/ui/common/views/jsonSchema/iteratees/showEnablePropertyIfAllPropertiesHidden.js
8479add466340fc65838703ff52b1285       1017  org/forgerock/openam/ui/main.js
f55bef3d19ec71f79e90c2db4ce37064       7034  org/forgerock/openam/ui/user/UserModel.js
53bf8a0e6358f2104e6b82f9ff15d0e6       3268  org/forgerock/openam/ui/user/anonymousProcess/AnonymousProcessView.js
4260a2e01f643fe5defbe6d117ebd571       1338  org/forgerock/openam/ui/user/anonymousProcess/ForgotUsernameView.js
52fab29b04b537125171b8475ba8e1fc       1326  org/forgerock/openam/ui/user/anonymousProcess/PasswordResetView.js
2e21497467c9093b475f052560ebcb57       2804  org/forgerock/openam/ui/user/anonymousProcess/SelfRegistrationView.js
24cc225985ee0838dee7ea0b4408ad4a       1111  org/forgerock/openam/ui/user/dashboard/main.js
a0f65b19fba4263289b2af69a27c3d6c       3468  org/forgerock/openam/ui/user/dashboard/services/DeviceManagementService.js
633181b787bd6c8cfead9735dc34e7c5       2047  org/forgerock/openam/ui/user/dashboard/services/MyApplicationsService.js
4c70401a34e40a232dad634a35b66618       1858  org/forgerock/openam/ui/user/dashboard/services/OAuthTokensService.js
88e98f88c9857db046566244305075f6       2419  org/forgerock/openam/ui/user/dashboard/services/PushDeviceService.js
cf8f7274dc90b8f5ce3ade795aa8d88b       1848  org/forgerock/openam/ui/user/dashboard/services/TrustedDevicesService.js
724a1b2f7ba512aff2211ded3ca47b69       9228  org/forgerock/openam/ui/user/dashboard/views/AuthenticationDevicesView.js
0bb836f339031f4ad76fa9e816eb7336       5407  org/forgerock/openam/ui/user/dashboard/views/DashboardView.js
d85af550548eb49413fd06ba950b1712       1511  org/forgerock/openam/ui/user/dashboard/views/DeviceDetailsDialog.js
d7a3854b143bc7a64b894489186094d5       2559  org/forgerock/openam/ui/user/dashboard/views/DevicesSettingsDialog.js
e9410ba7f08478ab87e14fdd64a2953b       1438  org/forgerock/openam/ui/user/dashboard/views/MyApplicationsView.js
ee285874e0fe25905f7717f777239ab1       2201  org/forgerock/openam/ui/user/dashboard/views/OAuthTokensView.js
242bc85b68309a2aa7ba754e761227b1       1926  org/forgerock/openam/ui/user/dashboard/views/TrustedDevicesView.js
ac3756c44ba648a069640ba0d5ecdbc1       1626  org/forgerock/openam/ui/user/login/LoginFailureView.js
797cdc83b1e220f458278f358a14bd26       1962  org/forgerock/openam/ui/user/login/RESTConfirmLoginView.js
4ad5785c234c7ce55f57c95e8e9daa37       1862  org/forgerock/openam/ui/user/login/RESTLoginDialog.js
9a523cf9183073915a3e240232bd7d85       7150  org/forgerock/openam/ui/user/login/RESTLoginHelper.js
d427117b8e202c84337d58fb68ad1258      21963  org/forgerock/openam/ui/user/login/RESTLoginView.js
e3dffe244d468383cfbda45b519176c9       2511  org/forgerock/openam/ui/user/login/RESTLogoutView.js
d73e946639ce2784d83a61b5860a909a       2540  org/forgerock/openam/ui/user/login/SessionExpiredView.js
99ee3f17cba8cc9c20107e6ae8c3f1c0       1773  org/forgerock/openam/ui/user/login/gotoUrl.js
81b3112dbd68b653dec9518de8cd952b       2035  org/forgerock/openam/ui/user/login/logout.js
a0aa3a0d3f7bfb363c09a851ed141a5c        927  org/forgerock/openam/ui/user/login/navigateThenRefresh.js
c60058aea6eef6db6930a7c218d3b093       2128  org/forgerock/openam/ui/user/login/tokens/AuthenticationToken.js
d89bf52f2f26d024aac5a0d976058f12       6089  org/forgerock/openam/ui/user/login/tokens/SessionToken.js
484f01913a48424009a5c934901cc305       1107  org/forgerock/openam/ui/user/main.js
de706c112eb004a0a1f40e728ee9da64       1929  org/forgerock/openam/ui/user/oauth2/OAuth2ConsentPageHelper.js
88d96400674e0ec39466b8c13ad04e10       6293  org/forgerock/openam/ui/user/oauth2/TokensView.js
d40ff4fa79b467374d278925a58f7515      11353  org/forgerock/openam/ui/user/services/AuthNService.js
68e8239fb6b831ab7787a9586eb412ee       1289  org/forgerock/openam/ui/user/services/KBADelegate.js
184c2f708a1058766c2f635116ced9c8       4664  org/forgerock/openam/ui/user/services/SessionService.js
b7dff54691a29d7c0c306f4e61ecb633       2605  org/forgerock/openam/ui/user/services/TokenService.js
0e2b97aa3afdf8909cc0bf128b383720       1386  org/forgerock/openam/ui/user/uma/main.js
bd808596f1259bf201d5af4e9bff332a       2072  org/forgerock/openam/ui/user/uma/models/UMAPolicy.js
7f3f061eab80220dd872bded370cd20b       1475  org/forgerock/openam/ui/user/uma/models/UMAPolicyPermission.js
9d0955784692b59da56bd0740c3dcb77       1774  org/forgerock/openam/ui/user/uma/models/UMAPolicyPermissionScope.js
b34b59ce30c8631940ffe48ab2cb040d       2750  org/forgerock/openam/ui/user/uma/models/UMAResourceSetWithPolicy.js
e956e2e8b16f9be22654a096e85047b0        958  org/forgerock/openam/ui/user/uma/models/User.js
67ac5ef80492ce95b91f4065649170cf       4426  org/forgerock/openam/ui/user/uma/services/UMAService.js
1f4077151a03614e20b36729a2d4185e       1413  org/forgerock/openam/ui/user/uma/util/URLHelper.js
3ce17257bc2580b84d454e6d886bd885       1374  org/forgerock/openam/ui/user/uma/views/backgrid/cells/PermissionsCell.js
be0acb6d003e85b42fef7568946d5b81       4350  org/forgerock/openam/ui/user/uma/views/history/ListHistory.js
11ffa7cbff8dda94e6fc9b8a5a3c40f6       4432  org/forgerock/openam/ui/user/uma/views/request/EditRequest.js
9bcae61c1daf0cc080493d35f4f13d0f       5548  org/forgerock/openam/ui/user/uma/views/request/ListRequest.js
cbf2d58f1db999f16b7f7e93111ad69b       5951  org/forgerock/openam/ui/user/uma/views/resource/BasePage.js
f412ba10b020434334a98ead98fdff0d       4782  org/forgerock/openam/ui/user/uma/views/resource/LabelTreeNavigationView.js
851dbe2ec95966e26d9af3bb96ae0269       3677  org/forgerock/openam/ui/user/uma/views/resource/MyLabelsPage.js
ff9ab356691e844fc057fe9a975131bb       4044  org/forgerock/openam/ui/user/uma/views/resource/MyResourcesPage.js
829d17e64a0fce78615f6a118f91760d      18881  org/forgerock/openam/ui/user/uma/views/resource/ResourcePage.js
2cc1588cbd29eb026407d61855777a0a       1172  org/forgerock/openam/ui/user/uma/views/resource/SharedWithMePage.js
0a765cd20e5593b30716378618b99128       1631  org/forgerock/openam/ui/user/uma/views/resource/StarredPage.js
6a11d42807d715c7c239c156b4e576d4       1479  org/forgerock/openam/ui/user/uma/views/share/BaseShare.js
01b6e7715bbedc46beecf52363b66da6      11385  org/forgerock/openam/ui/user/uma/views/share/CommonShare.js
5d7a1cc05074737bf91cc1a0369752e1       1791  org/forgerock/openam/ui/user/uma/views/share/ShareCounter.js
9f89fb5b5a1da88c62d1bdd56c3327ca        620  partials/alerts/_Alert.html
036070eb7b4b77d78ce7f79a068dc536        227  partials/breadcrumb/_Breadcrumb.html
1df13669cd8e6271b38330e2638e7564        699  partials/form/_AutoCompleteOffFix.html
f7d7895a8c45caf49c4e710851c608e4        225  partials/form/_Button.html
f2164438b059e9e06a34d9e53cba9dd1        369  partials/form/_JSONSchemaFooter.html
2c3039b3db0cbeffe09886eeeede4bf6        240  partials/form/_Select.html
0da89d78a19578a6b884a2109f956b4d        953  partials/form/_basicInput.html
87cabe270cb96121586a916dc67eb915        354  partials/form/_basicSaveReset.html
47815417f747eaf65b707b92dccc3d25        317  partials/headers/_Title.html
268bdcd72664d9744fce3f24dda1605d        855  partials/headers/_TitleWithSubAndIcon.html
5c1b59c01807b1f8ea2e937101a8991d       1022  partials/login/_Choice.html
c9dfe0da13988b89979556b745206789        202  partials/login/_Confirmation.html
854b83f3de415ce70e0fee63c888cb39        384  partials/login/_Default.html
e1340e1a7f2fe996d9d43d67bf035855         93  partials/login/_HiddenValue.html
f0d45e41c47d0c32d2f4a7b32dc9710f        397  partials/login/_Password.html
f9df91370d9b344946e23cbcd6a1541f         11  partials/login/_PollingWait.html
b3dee2592bc6cc6e6116576db59488c2         59  partials/login/_Redirect.html
3609c67f953d153207c54ad4b2d3415d        242  partials/login/_RememberLogin.html
f7e33e6ebe011e0e552cd9a5b577c548        293  partials/login/_ScriptTextOutput.html
d45f64e3b32e75d005b981245e9dff71        684  partials/login/_SelfService.html
84dcb7a2bd7042a894e4932e5b38422d        584  partials/login/_SocialAuthn.html
5c86a4e4ec1be8873f57b0d468af6530        201  partials/login/_TextInput.html
09e92d59cc6ffdc7570751d6572a39d2         94  partials/login/_TextOutput.html
90e6c8877399925813b0054b0f0c744d       1893  partials/process/_kbaItem.html
caf06db1a66f92ae49ef0fccd1607007       2715  partials/profile/_kbaItem.html
dbc82f20a6bece0acf145670b32ea584        217  partials/providers/_providerButton.html
728c3fb54d90349a9b330e2cb1737748        150  partials/util/_ButtonLink.html
8243491f3eaa8982890a8402bbd0207a        163  partials/util/_HelpLink.html
16a102457cbd9e648dbc31228e37b719        225  partials/util/_Status.html
e904e93430a29ddd6725744654beef02       1603  store/actions/creators.js
d94fff0eb7ef2ae9e855064d016e41bc       1237  store/actions/types.js
1707e0ef941275c2c1ba461a2f6be69b       1394  store/index.js
17f091ffac7c6a494e393a2a29897348       1346  store/reducers/index.js
c7ca09d74cd38b71af52b22eeb8c8449       1444  store/reducers/server.js
3a0078faae9876843fe57546dbeba337       1837  store/reducers/session.js
fdfcacc7e0d733b70cc63d30efc88781        129  templates/admin/backgrid/cell/IconAndDisplayNameCell.html
5686ea1da31ac619283d25c780e46fe9        133  templates/admin/backgrid/cell/IconAndNameCell.html
16078585d063d881b083f9b0a01bf8e6        364  templates/admin/backgrid/cell/RowActionsCell.html
463f0fdc1974436a28a289b4fa7afd40        235  templates/admin/backgrid/cell/StatusCell.html
1ef9803be6a204627b1123ce680d87af        179  templates/admin/views/common/BackLink.html
68446ddba50205d9cd8f576dd1ebef53         64  templates/admin/views/common/HeaderFormTemplate.html
69e2eeab0fa3a0ea1590d30475ac52f3        147  templates/admin/views/common/IframeViewTemplate.html
ef3f3402093fc563084978b7ac6df197        928  templates/admin/views/common/ToggleCardListTemplate.html
5151948b60e84cd57449b612368c2a78       2234  templates/admin/views/common/navigation/TreeNavigationTemplate.html
69fb44efafda97923fad63956995d192        710  templates/admin/views/common/navigation/_TreeNavigationLeaf.html
b311c4b462a5018d9fcec6fedf425d33        409  templates/admin/views/common/schema/EditServiceSubSchemaTemplate.html
154b1829fcce2338f4e5b09bfc9d6703        393  templates/admin/views/common/schema/EditServiceSubSubSchemaTemplate.html
68e0d4efbe127b6b09f7124f7a586e04       1000  templates/admin/views/common/schema/NewServiceSubSchemaTemplate.html
233ec1473856c0010f3c636f7a1e271b         82  templates/admin/views/configuration/EditGlobalConfigurationBaseTemplate.html
813782affecb34b695e5f15e7036d7dc        339  templates/admin/views/configuration/EditGlobalConfigurationTemplate.html
2216cb2d85af45a357312072cbd16273        334  templates/admin/views/configuration/ListConfigurationTemplate.html
7e1ed4edf4957d050b77e1236747bf1e       3857  templates/admin/views/configuration/global/SubSchemaListTemplate.html
722e3263900f77932b18396163f3a873       1349  templates/admin/views/configuration/global/SubSubSchemaListTemplate.html
1c8318ab4b6bbd1ca0886a356e1f7b63        499  templates/admin/views/deployment/servers/ListServersTemplate.html
8e999460cf227306932e9e8928b3ffb1       1163  templates/admin/views/deployment/servers/NewServerTemplate.html
9f98fb2f7ce41dfbba41520056349324         89  templates/admin/views/deployment/servers/ServersCardsTemplate.html
deed99b6d70ef1a07d45e048cddbaf4c       1207  templates/admin/views/deployment/servers/ServersTableTemplate.html
2ce8eb2848ff7cb42b52846951ee7737       1478  templates/admin/views/deployment/servers/_ServerCard.html
93ab31de831be63dadd3e311ac5e8807        657  templates/admin/views/deployment/sites/EditSiteTemplate.html
9889462fb1996ce0999a31ed0a3d7ba1        491  templates/admin/views/deployment/sites/ListSitesTemplate.html
b9357296e02d23d81586225b0f0eb2c5       1326  templates/admin/views/deployment/sites/NewSiteTemplate.html
20acb9673347f75bd02879e45fc50d92         85  templates/admin/views/deployment/sites/SitesCardsTemplate.html
abc6f9f2897267b28960dbb9eb5e491c       1380  templates/admin/views/deployment/sites/SitesTableTemplate.html
5da8abe9aa048e4865e093120d8ad780       1307  templates/admin/views/deployment/sites/_SiteCard.html
1ae49763d5c9440f6e50fbac9c02fd84       1155  templates/admin/views/realms/EditRealmTemplate.html
cd4b6689cdaa0c982686d80d1e738c4b        193  templates/admin/views/realms/ListRealmsTemplate.html
6ff4195e93e23f9f91f4b7b6f55614c0         76  templates/admin/views/realms/RealmsCardsTemplate.html
4652c08c335d69bb426aba675220ce70       2056  templates/admin/views/realms/RealmsTableTemplate.html
fbf82c253b050bd1c8143e78ac57bba9       2345  templates/admin/views/realms/_RealmCard.html
5b3f00d594920af83b7682ebff0ae770        736  templates/admin/views/realms/applications/agents/NewAgentTemplate.html
0c6d9d94606245158554baa280bfb66b       2644  templates/admin/views/realms/authentication/ChainsTemplate.html
ec90f6f25643057ffca7f23422de0ed3       2881  templates/admin/views/realms/authentication/ModulesTemplate.html
56675f3d51cdfae0213adbf99b48b60b         82  templates/admin/views/realms/authentication/SelectModuleItem.html
4d5062e2f1788096762a3fb44b1bf14d         94  templates/admin/views/realms/authentication/SelectModuleOption.html
aff1b4740c8e46b3c756ef683e0ce10a        708  templates/admin/views/realms/authentication/SettingsTemplate.html
9c6462ecb4386a785f8710b40cf81597       1039  templates/admin/views/realms/authentication/chains/AddChainTemplate.html
c1223aaa9598b51103326b087d52d1cc       5834  templates/admin/views/realms/authentication/chains/EditChainTemplate.html
6339bd0ff958c78ed0da618ecf71a247       1538  templates/admin/views/realms/authentication/chains/EditLinkTableTemplate.html
95f33bd03964fba05951b2df2a437ece        486  templates/admin/views/realms/authentication/chains/EditLinkTemplate.html
380e3ec4bc2cfde200590c051b562f75       2296  templates/admin/views/realms/authentication/chains/LinkTemplate.html
689763604886ca970923f0e11b5fa158        120  templates/admin/views/realms/authentication/chains/PopoverTemplate.html
192b12cefb46b42eb9c601315ae45261       1035  templates/admin/views/realms/authentication/chains/PostProcessTemplate.html
6066f6670447adb7199b965158de830d       2115  templates/admin/views/realms/authentication/chains/_CriteriaFooter.html
ebf971b29041c25ec5a1d15108c6f863       1342  templates/admin/views/realms/authentication/modules/AddModuleTemplate.html
3d65199bc5fc3ba5ff4a3932910d1958       1002  templates/admin/views/realms/authentication/modules/EditModuleViewTemplate.html
ecd861a18ac313300b6618eea6092262       1453  templates/admin/views/realms/authorization/common/ActionsTableTemplate.html
e94a53ad449c5d52f6e72ad6e9cf0639        562  templates/admin/views/realms/authorization/common/StripedListItemTemplate.html
8258fbcc2fe97b7193d47ff5dee427a6        338  templates/admin/views/realms/authorization/common/StripedListWrapperTemplate.html
4b47d3a8311238a1ba64b8b60c0aef73       1634  templates/admin/views/realms/authorization/policies/CreatedResourcesTemplate.html
02ee7ba7d016ec4732ed63a2c445c16b       6051  templates/admin/views/realms/authorization/policies/EditPolicyTemplate.html
8ab6c3b408bbe066cf109d6174d5f6c1       1886  templates/admin/views/realms/authorization/policies/NewPolicyTemplate.html
a9dacf0a59bd04f7063bd13df3e7bb26        630  templates/admin/views/realms/authorization/policies/PoliciesTemplate.html
0265e3c88578a11dd5e1bf4fc44ac3a1        155  templates/admin/views/realms/authorization/policies/PoliciesToolbarTemplate.html
5c65bf3608c083cecce5f96295d11b00         86  templates/admin/views/realms/authorization/policies/PolicyActionsTemplate.html
ea7c79c254cfd9b93905fb600f953567        475  templates/admin/views/realms/authorization/policies/PolicyAvailableActionsTemplate.html
b533c6e1707bcdaa05a9287302468be2        339  templates/admin/views/realms/authorization/policies/PopulateResourceTemplate.html
96465f0f8de48840453d8f18c46feb86        957  templates/admin/views/realms/authorization/policies/StripedListActionItemTemplate.html
1bcfcc6cfcb6ef18e052a94e42ea2679        501  templates/admin/views/realms/authorization/policies/attributes/CustomAttributesTemplate.html
89376d686309e46871028638c49cddbd        527  templates/admin/views/realms/authorization/policies/attributes/SubjectAttributesTemplate.html
0a5c714bd31bd6c5bc1045873b783f72        308  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrArray.html
73bb57ba1c7e6b1823903886ff042ae0        476  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrBoolean.html
17ece1ec69e65b825ff781597132c8bb        748  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrDate.html
ec17490c547931996c67cb104604c406        992  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrDay.html
ed1d858e9d0d600e91ad55dd455f0387        368  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrEnum.html
4678ce2fee07d1d50d10b775b8ef229c        418  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrObject.html
1d8d24f5f7e19dea25edcbcc2cfbdd4b        269  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrString.html
eb83392b4a792804a29cfbb6d5b04f73        986  templates/admin/views/realms/authorization/policies/conditions/ConditionAttrTime.html
99533a957462718519dddd4fc9835b45       1185  templates/admin/views/realms/authorization/policies/conditions/EditEnvironmentTemplate.html
d09bc2008a50e9942d471a920bb4ec59        894  templates/admin/views/realms/authorization/policies/conditions/EditSubjectTemplate.html
289c5c1969046a87ed9baae0c9d7369c        798  templates/admin/views/realms/authorization/policies/conditions/LegacyListItem.html
56c236a575d07d8a3aa71ef81e49fd0c        593  templates/admin/views/realms/authorization/policies/conditions/ListItem.html
c50a603c5b4c60a70cb9696e919f03f4        830  templates/admin/views/realms/authorization/policies/conditions/ManageRulesTemplate.html
d9ff96421c16b5021aa47b78cb6e64ee        645  templates/admin/views/realms/authorization/policies/conditions/OperatorRulesTemplate.html
9798fc2dc41b0572c705447bc12d6c67       1279  templates/admin/views/realms/authorization/policySets/EditPolicySetTemplate.html
fe57913a329d4a138fa21472cee53382        533  templates/admin/views/realms/authorization/policySets/NewPolicySetTemplate.html
081a920c41e17837248a9825fd282d24       1932  templates/admin/views/realms/authorization/policySets/PolicySetSettingsTemplate.html
4c8dabe18a572707204ae98f95c94f2e       1690  templates/admin/views/realms/authorization/policySets/PolicySetsTemplate.html
b8a76b11c3b56b1f4406b69f851081fd        580  templates/admin/views/realms/authorization/policySets/PolicySetsToolbarTemplate.html
d10949a68e812fe8abe1a1956369ab2f       1782  templates/admin/views/realms/authorization/resourceTypes/EditResourceTypeTemplate.html
96db9f4f3e6951d7872be68f1df9dbfe       1348  templates/admin/views/realms/authorization/resourceTypes/NewResourceTypeTemplate.html
007abd46cd28c19ca687b7858b83264d        750  templates/admin/views/realms/authorization/resourceTypes/ResourceTypeSettingsTemplate.html
47bf3238e71c553f859fce99f0cc5dfa        425  templates/admin/views/realms/authorization/resourceTypes/ResourceTypesActionsTemplate.html
c560a52b3918051d1378fe82868f48b3        938  templates/admin/views/realms/authorization/resourceTypes/ResourceTypesPatternsTemplate.html
55c4db40799724272e1f443fc644f0b3        871  templates/admin/views/realms/authorization/resourceTypes/ResourceTypesTemplate.html
2696552381b117efdfb7c9e82e5ba4f8        142  templates/admin/views/realms/authorization/resourceTypes/ResourceTypesToolbarTemplate.html
683c54faf99bcf97dda636f20eab2460       1359  templates/admin/views/realms/dashboard/DashboardTasksTemplate.html
06b152029d50d47afb63e73b0fc27113        768  templates/admin/views/realms/dashboard/DashboardTemplate.html
2b405e895aacb27637cd17da1ac8c60b        449  templates/admin/views/realms/scripts/ChangeContextTemplate.html
b756d55d1108152dd37cde6b0559755c       3964  templates/admin/views/realms/scripts/EditScriptTemplate.html
0c88cf215614a9afc276071dbf8a5908       1552  templates/admin/views/realms/scripts/NewScriptTemplate.html
874e3340dc6fd53226497c274ebc61a6       1258  templates/admin/views/realms/scripts/ScriptValidationTemplate.html
2ecdc7e6e831366b8344dcd9d7c3047c        283  templates/admin/views/realms/scripts/ScriptsTemplate.html
8a094abcb37bd916eacac7005d1c63a9        390  templates/admin/views/realms/scripts/ScriptsToolbarTemplate.html
5562c36ff81d46f5fad31964162818cb        419  templates/admin/views/realms/services/EditServiceTemplate.html
c43cc9ebf8915bc497abaf23d2cbacf3       1966  templates/admin/views/realms/services/NewServiceTemplate.html
e4a6aba9cfe2336438aa6ef3b58aa0af       2898  templates/admin/views/realms/services/ServicesTemplate.html
d5a147978444902b65f9cff5ca9c53e0       3551  templates/admin/views/realms/services/SubSchemaListTemplate.html
7cd4452e381b14ea4a315463e4951c6c        293  templates/common/404.html
1e6721e37a291caafd78b1abd47b4d07        406  templates/common/ChangesPendingTemplate.html
1a383d670bb012a732987f9e96be9786        210  templates/common/DefaultBaseTemplate.html
a647ea625d6643c29966c34e956b9d3d        894  templates/common/DialogTemplate.html
be6f65c1e8b926c2429a32ea1763c644         97  templates/common/EmptyTemplate.html
79a01c1996013b1056508f6e11f4e869        178  templates/common/EnableCookiesTemplate.html
b37b61653e3b14d09c469934cc576097        520  templates/common/FooterTemplate.html
f67a239d35f1b13b7e886a94850e6ee2        465  templates/common/LoginBaseTemplate.html
e8246c6ef78aad67abc4b839802b4c53        581  templates/common/LoginDialog.html
958dfcc31578677613a721c587350c63        389  templates/common/LoginHeaderTemplate.html
483fd355b29b66a138a4314294d0d26c       2963  templates/common/LoginTemplate.html
c332f3f2d85b422b2a594bf22565d405        540  templates/common/MediumBaseTemplate.html
62ee926e4521ba98d9bb25f2cb2a99d0       9296  templates/common/NavigationTemplate.html
6259cef63988fd97e8d8288a97543af9        455  templates/common/UnauthorizedTemplate.html
9f8963f2281d7e725d32407d9a1083d5        169  templates/common/components/PanelComponentTemplate.html
e2a3ec6025372aad1ffaae72637b7c70         98  templates/common/components/SelectComponent.html
39534ee345c6e9b2b0d68f24f964966b        164  templates/common/components/tab/TabComponentBodyTemplate.html
7926f8da592b081f5de5fe59ff3456f3        375  templates/common/components/tab/TabComponentTemplate.html
e18f83bcdbcb9e784fa0c20903bdd511        871  templates/common/components/table/EditRow.html
238cbe2cd083fe3c9fba991e7539426b        296  templates/common/components/table/InlineEditTable.html
601c6176637656a5cbd0322c3c2da818        764  templates/common/components/table/NewRow.html
a3da0b7ed370f9980f7397c70ab2dbf0        367  templates/common/components/table/ReadOnlyRow.html
6a5b0216f02ae5336269fa85d7058922        232  templates/common/error/403.html
b8cc076727f06f24bd7759ae4056728f        659  templates/common/jsonSchema/editors/TogglableJSONEditorTemplate.html
de6be2d63321511409cdfa8253676133        187  templates/common/jsonSchema/editors/_HelpPopover.html
71bf1bfc587cb73d630fa6e37994ed2b       2246  templates/openam/ChangeSecurityDataDialogTemplate.html
eb8cf7dba4717ae37016bac05a10c2bf        952  templates/openam/RESTLoginTemplate.html
695ac478014943ec947f71f5381d567a        339  templates/openam/ReturnToLoginTemplate.html
2079d436ab4c2d41f309d084400b05ee       1398  templates/openam/authn/AuthenticatorPush3.html
b51f8a232d734cc5ae2f237d1411b1a5       1021  templates/openam/authn/AuthenticatorPushRegistration3.html
2d8a1f8eabe697a5f67f4ad844f3d5b5        797  templates/openam/authn/AuthenticatorPushRegistration4.html
af7627d3f957c76112a9a0a583c5641a        933  templates/openam/authn/DataStore1.html
03c0bab78fe1f89a9e8c4b98c181470c        516  templates/openam/authn/DeviceIdMatch2.html
458eaccc57dfdb241de169c54f9929c9       1240  templates/openam/authn/QRnull.html
b84674bf4539c55f2604d6978fc418bb        864  templates/openam/authn/ReCaptcha1.html
05e9e8711cd979da301b96f5cbec67ef       1055  templates/openam/authn/WebAuthnAuthentication2.html
8af642c450fe2407c7483b7db8dd6828       1053  templates/openam/authn/WebAuthnRegistration2.html
a9f56b7e87f0c13885f5d152cb1944d8        263  templates/user/AnonymousProcessBaseTemplate.html
a445b7a2199bea1ef562cac49bf51575        742  templates/user/AnonymousProcessWrapper.html
77ecba60fabbb5f3c113ad0ee26a73e4       6598  templates/user/AuthorizeTemplate.html
6e7d5448665b0262ca6d90f4aa0af204        774  templates/user/ConfirmPasswordDialogTemplate.html
a50f158d31ebe3cae6d801e33c68735a        128  templates/user/DeviceDoneTemplate.html
20e96959c86ef1772a5db31fea394b30        993  templates/user/DeviceTemplate.html
dc37d87bf809a0cd109b68c7482c1920        882  templates/user/UserProfileKBATab.html
2366b0079dff4108bfe630e4184391e4       3701  templates/user/UserProfileTemplate.html
7fc17f0a98b1f690791c81534d3a734f       3005  templates/user/dashboard/AuthenticationDevicesTemplate.html
1acf21e7b0218650ace9318443a987ae        413  templates/user/dashboard/DashboardTemplate.html
961c7408d921038c573cbca190db65ec       3074  templates/user/dashboard/DeviceManagementTemplate.html
4309466d053f75c4d787063fbe5eba90        917  templates/user/dashboard/DevicesSettingsDialogTemplate.html
908fa774d36e2d61471b2293c551442e        737  templates/user/dashboard/EditDeviceDialogTemplate.html
92bcdd2ec7fdeb8d5a089c9c0ea6e444        998  templates/user/dashboard/MyApplicationsTemplate.html
978bde463197d6630d1e9a4f47ffde33       2238  templates/user/dashboard/TokensTemplate.html
6d5a981bc960d7cfb59b1e919bd027b9       2052  templates/user/dashboard/TrustedDevicesTemplate.html
fd8be9a52721e34831b64322ddf5ffb1        375  templates/user/process/GenericEndPage.html
ed73de6a480c1f0c2bd425bccd1eb24a        617  templates/user/process/GenericInputForm.html
cf4f12c3ca66a898a8372faf4d279eb3       2306  templates/user/process/KBAQuestionTemplate.html
790c92aab6846051bcff0916ea0c0a73        305  templates/user/process/KBATemplate.html
b5cc54b949358dea8738aa36d0766e3e        593  templates/user/process/registration/captcha-initial.html
eaaff8a579fbd783cb2f033818eed428        959  templates/user/process/registration/emailValidation-initial.html
8b975f956464fd5f7d5012c04a81c263        290  templates/user/process/registration/emailValidation-validateCode.html
9acce44fcf6745b002b018e7c21eb558        341  templates/user/process/registration/kbaSecurityAnswerDefinitionStage-initial.html
b82588524adcfa861f3aef95026d6d36        514  templates/user/process/registration/termsAndConditions-initial.html
fcb95166554d8173c5bffd75ab5da7c5       2154  templates/user/process/registration/userDetails-initial.html
b5cc54b949358dea8738aa36d0766e3e        593  templates/user/process/reset/captcha-initial.html
1171da9106dad2040375392e3bcb9f1d        671  templates/user/process/reset/emailValidation-initial.html
8b975f956464fd5f7d5012c04a81c263        290  templates/user/process/reset/emailValidation-validateCode.html
ee2988c574c5d480420b593d141684f0       1011  templates/user/process/reset/kbaSecurityAnswerVerificationStage-initial.html
5b825ad83ceb2558f5e1adf0ff68607e       1284  templates/user/process/reset/resetStage-initial.html
cc5d656c1b277a4426df777cc60308e7       3288  templates/user/process/reset/userQuery-initial.html
b5cc54b949358dea8738aa36d0766e3e        593  templates/user/process/username/captcha-initial.html
a2e8aae82da9fde69d245341f2accd0c        190  templates/user/process/username/emailUsername-end.html
820def30d73fe9c03f8eab292f398262       1090  templates/user/process/username/kbaSecurityAnswerVerificationStage-initial.html
4331425b147a8091d9a4a65d63174275        225  templates/user/process/username/retrieveUsername-end.html
d3a24d830307c108ecd5794c2b786c06       1990  templates/user/process/username/userQuery-initial.html
7addb2df7affc445c1f5c7af60658ee2        258  templates/user/uma/backgrid/cell/ActionsCell.html
91792ecc17d92947353625405db97d41        161  templates/user/uma/backgrid/cell/PermissionsCell.html
e75e5f0bff93e56843c1e19600c0a777        475  templates/user/uma/backgrid/cell/RevokeCell.html
2f2cee2bcb9555af8f7865fb04017409        124  templates/user/uma/backgrid/cell/SelectizeCell.html
75475ade6a67b2e69e4722cce6a09608        111  templates/user/uma/backgrid/cell/ShareBtnCell.html
528e0823212c2edab8fbd82f773925d2        541  templates/user/uma/bootstrap/BootstrapModalShareTemplate.html
a4bbcfff59e3b2787faadb1f2e6b53cc        348  templates/user/uma/views/history/ListHistory.html
e29c75e4b1f695e524709e525955354a        666  templates/user/uma/views/request/EditRequestTemplate.html
b2ba735f20ce22c7c2b01e8cd30c931b        360  templates/user/uma/views/request/ListRequestTemplate.html
c740c4c81f068db664b7954bf2626407       2434  templates/user/uma/views/resource/LabelTreeNavigationTemplate.html
a828a671cde02b4e5ad79d3c6bee34a0        125  templates/user/uma/views/resource/ListResourceTab.html
15fcffa1414e23384299b2f908e24f34        658  templates/user/uma/views/resource/MyLabelsPageTemplate.html
9c400b8c359edcfc8434f84ad65b3b47        417  templates/user/uma/views/resource/MyResourcesPageTemplate.html
ccce9e145deb71800e9090e82637cbf7       2079  templates/user/uma/views/resource/ResourceTemplate.html
63e418bd62b2c6dc2620907d1e04356a        268  templates/user/uma/views/resource/SharedWithMePageTemplate.html
27dd569c705818e90863e49d827e6794        258  templates/user/uma/views/resource/StarredPageTemplate.html
31c10979c03342e32e12335a5c5ae056        163  templates/user/uma/views/resource/_DeleteLabelButton.html
9df9a1c7642d11c76a9d0192218d71fb        860  templates/user/uma/views/resource/_NestedList.html
0f43f1057a4bdd82fd541006189c9ca2        182  templates/user/uma/views/resource/_UnshareAllResourcesButton.html
3b4f3e54af90c3455f7feb588a7d2dc5         47  templates/user/uma/views/share/BaseShare.html
84dd535a8aa8cb4824e7994c3776ddcd       2047  templates/user/uma/views/share/CommonShare.html
6f491c1b3c66d8a37b0399d843f6e779        278  templates/user/uma/views/share/ShareCounter.html
9732121ea87d7a468e88f2c2dac1ec4a      18390  themes/dark/config.json
db501e89adfc3af96dc159fb3c98fb82     111609  themes/dark/css/bootstrap.min.css
e519986f83b312f24993746ddd291bdd        971  themes/dark/css/theme-dark.css
b9eae7755a3dcb26a4ef426cf6376635      12099  themes/dark/images/login-logo-white.png
1c7df355ca50bcd4915fcb237b3f5d72      15063  timezones.json
```
