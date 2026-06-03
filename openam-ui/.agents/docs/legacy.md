# Legacy Backbone Tasks

These tasks apply to the Backbone.js codebase (`src/main/js/`). For Vue migration tasks, see `vue-migration.md`.

## Adding a new admin UI view

1. Create an AMD module under `src/main/js/org/forgerock/openam/ui/admin/views/`
2. Register the route in the appropriate router module
3. Add a Handlebars template (`.html`) in the corresponding `templates/` directory
4. Externalise all strings to the i18n bundle
5. Write a QUnit test in `src/test/`
6. Run `npx grunt` and verify no ESLint errors and all tests pass

## Updating a REST API call

1. Edit or add the relevant service file under `openam-ui-api/src/main/js/`
2. Use the existing Axios instance — do not create raw `fetch()` or `XMLHttpRequest` calls
3. Bump the affected test fixtures and run `npm test`

## Changing a shared third-party library version

1. Update the `<version>` in the matching `<artifactItem>` block in `openam-ui/pom.xml`
2. Update `<downloadUrl>` if the CDN path changed
3. Run `mvn process-resources -pl openam-ui` to verify the download succeeds
4. Run `mvn package -pl openam-ui` and confirm the full Grunt pipeline passes
