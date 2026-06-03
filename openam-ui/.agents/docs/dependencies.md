# Third-Party Dependency Management

## How it works

All vendored JS/CSS libraries are **not committed to source**. They are downloaded by Maven during `process-resources` from CDNs (cdnjs, unpkg, raw.githubusercontent.com) and placed under `target/dependencies/`.

To add or update a library, edit the `<artifactItems>` list in `openam-ui/pom.xml`. Use the existing `<downloadUrl>` template variables (`{version}`, `{artifactId}`, `{classifier}`, `{packaging}`).

## Key Libraries

| Category | Libraries |
|---|---|
| UI framework | Backbone.js 1.1.2, Backbone Paginator 2.0.2, Backbone-Relational 0.9.0 |
| Grid | Backgrid 0.3.5 (with paginator, filter, select-all extensions) |
| Templating | Handlebars 4.7.7 |
| DOM | jQuery 3.7.1, jQuery Placeholder, jQuery Sortable, jQuery ba-dotimeout |
| Styles | Bootstrap 3.3.5, Font Awesome 4.5.0, Selectize 0.12.1, Dragula 3.6.7, Bootstrap Dialog 1.34.4, Bootstrap Clockpicker, Bootstrap DateTimePicker |
| Module loader | RequireJS 2.3.7 (r.js optimizer), RequireJS text plugin 2.0.15 |
| i18n | i18next 1.7.3 |
| React (legacy) | React 15.2.1, ReactDOM, react-bootstrap 0.30.1, react-select 1.0.0-rc.2 |
| State | Redux 3.5.2 |
| Utilities | Lodash 2.4.1 / 3.10.1, Moment.js 2.28.0, XDate 0.8, spin.js, base64, form2js / js2form, QRCode, JSON Editor 0.7.9 |
| Editor | CodeMirror 4.10 |
| Testing | QUnit 1.15.0, Sinon.js 1.15.4, Squire.js 0.2.0 (AMD mock injector) |

## Update Process

1. Update the `<version>` in the matching `<artifactItem>` block in `openam-ui/pom.xml`
2. Update `<downloadUrl>` if the CDN path changed
3. Run `mvn process-resources -pl openam-ui` to verify the download succeeds
4. Run `mvn package -pl openam-ui` and confirm the full Grunt pipeline passes
