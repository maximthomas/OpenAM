/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems LLC.
 */

/* global module, require, process */

var _ = require("lodash"),
    mavenSrcPath = "/src/main/js",
    mavenTestPath = "/src/test/js";

function mavenProjectSource (projectDir) {
    return [
        projectDir + mavenSrcPath,
        projectDir + "/src/main/resources"
    ];
}

function mavenProjectTestSource (projectDir) {
    return [
        projectDir + mavenTestPath,
        projectDir + "/src/test/resources"
    ];
}

module.exports = function (grunt) {
    var compositionDirectory = "target/XUI",
        compiledDirectory = "target/compiled",
        transpiledDirectory = "target/transpiled",
        testClassesDirectory = "target/test-classes",
        forgeRockCommonsDirectory = process.env.FORGEROCK_UI_SRC + "/forgerock-ui-commons",
        forgeRockUiDirectory = process.env.FORGEROCK_UI_SRC + "/forgerock-ui-user",
        targetVersion = grunt.option("target-version") || "dev",
        commonsPackageSource = function (pkg) {
            return [
                "node_modules/@openidentityplatform/" + pkg + "/amd",
                "node_modules/@openidentityplatform/" + pkg + "/www"
            ];
        },
        // The npm-installed sources, tracked separately: only these carry a root package.json
        // that must not reach the UI. See copy:compose below.
        npmPackageDirs = _.flatten([
            commonsPackageSource("ui-commons"),
            commonsPackageSource("ui-user")
        ]),
        buildCompositionDirs = _.flatten([
            // TASK 4.7. The runtime libraries, staged from node_modules rather than unpacked from
            // the org.openidentityplatform.commons.ui.libs Maven artifacts, which are retired.
            // PRODUCED BY THE VITE BUILD (vite.config.js, stageNpmLibraries) - Grunt has no step
            // that creates it, so `npm run build:grunt` now requires a `npm run build:production`
            // to have run first. Grunt stopped being the production pipeline in task 4.1 and is
            // deleted in group 5; this is deliberately not worth a second copy of the file map.
            "target/npm-libs",
            // target/dependencies is GONE (4.8). It held only CodeMirror after 4.7 - 4 files under
            // libs/codemirror, 2 under css/codemirror - and 4.8 moved those to npm alongside every
            // other runtime library, so the dir.xml descriptor, the prepare-working-dir execution
            // that ran it and the maven-dependency-plugin unpack that fed it are all deleted.
            // Nothing produces this directory any more; do not re-add it.
            //
            // When building, the commons sources are installed by Maven+npm as tarball packages
            npmPackageDirs,
            // target/dependencies-expanded/forgerock-ui-user is GONE (4.7). It held exactly one
            // file, libs/form2js-2.0-769718a.js, unpacked from the commons www zip to pin which
            // of two disagreeing builds AM shipped. form2js has no npm package under any name -
            // maxatwork/form2js @769718a was never published - so those exact bytes are now
            // vendored in src/main/js/libs, which composes below. The pin, the unpack execution
            // and the commons.ui:user:zip:www dependency all retire with it.
            // This must come last so that it overwrites any conflicting files!
            mavenProjectSource(".")
        ]),
        watchCompositionDirs = _.flatten([
            // When watching, we want to get the dependencies directly from the source
            mavenProjectSource(forgeRockCommonsDirectory),
            mavenProjectSource(forgeRockUiDirectory),
            // This must come last so that it overwrites any conflicting files!
            mavenProjectSource(".")
        ]),
        testWatchDirs = _.flatten([
            mavenProjectTestSource(".")
        ]),
        testInputDirs = _.flatten([
            mavenProjectTestSource(".")
        ]),
        nonCompiledFiles = [
            "**/*.html",
            "**/*.ico",
            "**/*.json",
            "**/*.png",
            "**/*.eot",
            "**/*.svg",
            "**/*.woff",
            "**/*.woff2",
            "**/*.otf",
            "css/bootstrap-3.3.5-custom.css",
            "themes/**/*.*"
        ],
        serverDeployDirectory = process.env.OPENAM_HOME + "/XUI";

    grunt.initConfig({
        babel: {
            options: {
                env: {
                    development: {
                        sourceMaps: true
                    }
                },
                ignore: ["libs/"],
                presets: [
                    ["@babel/preset-env", { "targets": "> 0.2%, not dead, last 2 versions" }],
                    "@babel/preset-react"],
                plugins: [["@babel/plugin-transform-classes", { "loose": true }]]
            },
            transpileJS: {
                files: [{
                    expand: true,
                    cwd: compositionDirectory,
                    src: ["**/*.js", "!libs/**/*.js"],
                    dest: transpiledDirectory
                }]
            },
            transpileJSM: {
                files: [{
                    expand: true,
                    cwd: compositionDirectory,
                    src: ["**/*.jsm", "**/*.jsx"],
                    dest: transpiledDirectory,
                    rename: function (dest, src) {
                        return dest + "/" + src.replace(".jsm", ".js").replace(".jsx", ".js");
                    }
                }],
                options: {
                    plugins: ["@babel/plugin-transform-modules-amd"]
                }
            }
        },
        copy: {
            /**
             * Copy all the sources and resources from this project and all dependencies into the composition directory.
             *
             * TODO: This copying shouldn't really be necessary, but is required because the dependencies are all over
             * the place. If we move to using npm for our dependencies, this can be greatly simplified.
             */
            compose: {
                files: buildCompositionDirs.map(function (dir) {
                    return {
                        expand: true,
                        cwd: dir,
                        // "!package.json" drops the CommonJS marker at the root of each npm
                        // package's amd/ directory; it is not part of the UI. Scoped to those
                        // directories rather than applied to all of them, so that a future
                        // composition source which legitimately ships a root package.json does
                        // not lose it silently.
                        src: _.includes(npmPackageDirs, dir) ? ["**", "!package.json"] : ["**"],
                        dest: compositionDirectory
                    };
                })
            },
            /**
             * Copy files that do not need to be compiled into the compiled directory.
             */
            compiled: {
                files: [{
                    expand: true,
                    cwd: compositionDirectory,
                    src: nonCompiledFiles.concat([
                        "!main.js", // Output by r.js
                        "!index.html" // Output by grunt-text-replace
                    ]),
                    dest: compiledDirectory
                }]
            },
            /**
             * Copy files that have been transpiled into the compiled directory.
             */
            transpiled: {
                files: [{
                    expand: true,
                    cwd: transpiledDirectory,
                    src: [
                        "**/*.js",
                        "!main.js" // Output by r.js
                    ],
                    dest: compiledDirectory
                }]
            },
            libraries: {
                files: [{
                    expand: true,
                    cwd: compositionDirectory,
                    src: ["libs/**/*.js"],
                    dest: transpiledDirectory
                }]
            }
        },
        eslint: {
            /**
             * Check the JavaScript source code for common mistakes and style issues.
             */
            lint: {
                src: [
                    "." + mavenSrcPath + "/**/*.js",
                    "." + mavenSrcPath + "/**/*.jsm",
                    "." + mavenSrcPath + "/**/*.jsx",
                    "!." + mavenSrcPath + "/libs/**/*.js",
                    "." + mavenTestPath + "/**/*.js"
                ],
                options: {
                    format: require.resolve("eslint-formatter-warning-summary")
                }
            }
        },
        karma: {
            options: {
                configFile: "karma.conf.js"
            },
            build: {
                singleRun: true,
                reporters: ["progress"]
            },
            dev: {
            }
        },
        less: {
            /**
             * Compile LESS source code into minified CSS files.
             */
            compile: {
                files: [{
                    src: compositionDirectory + "/css/structure.less",
                    dest: compiledDirectory + "/css/structure.css"
                }, {
                    src: compositionDirectory + "/css/theme.less",
                    dest: compiledDirectory + "/css/theme.css"
                }, {
                    src: compositionDirectory + "/css/styles-admin.less",
                    dest: compiledDirectory + "/css/styles-admin.css"
                }],
                options: {
                    compress: true,
                    plugins: [
                        new (require("less-plugin-clean-css"))({})
                    ],
                    relativeUrls: true
                }
            }
        },
        replace: {
            /**
             * Include the version of AM in the index file.
             *
             * This is needed to force the browser to refetch JavaScript files when a new version of AM is deployed.
             */
            buildNumber: {
                src: compositionDirectory + "/index.html",
                dest: compiledDirectory + "/index.html",
                replacements: [{
                    from: "${version}",
                    to: targetVersion
                }]
            }
        },
        requirejs: {
            /**
             * Concatenate and uglify the JavaScript.
             */
            compile: {
                options: {
                    baseUrl: transpiledDirectory,
                    mainConfigFile: transpiledDirectory + "/main.js",
                    out: compiledDirectory + "/main.js",
                    include: ["main"],
                    preserveLicenseComments: false,
                    generateSourceMaps: true,
                    optimize: "uglify2",
                    // These files are excluded from optimization so that the UI can be customized without having to
                    // repackage it.
                    excludeShallow: [
                        "config/AppConfiguration",
                        "config/ThemeConfiguration"
                    ]
                }
            }
        },
        /**
         * Sync is used when watching to speed up the build.
         */
        sync: {
            /**
             * Copy all the sources and resources from this project and all dependencies into the composition directory.
             */
            compose: {
                files: watchCompositionDirs.map(function (dir) {
                    return {
                        cwd: dir,
                        src: ["**"],
                        dest: compositionDirectory
                    };
                }),
                compareUsing: "md5"
            },
            /**
             * Copy files that do not need to be compiled into the compiled directory.
             *
             * Note that this also copies main.js because the requirejs step is not being performed when watching (it
             * is too slow).
             */
            compiled: {
                files: [{
                    cwd: compositionDirectory,
                    src: nonCompiledFiles.concat([
                        "!index.html" // Output by grunt-text-replace
                    ]),
                    dest: compiledDirectory
                }],
                compareUsing: "md5"
            },
            /**
             * Copy files that have been transpiled (with their source maps) into the compiled directory.
             */
            transpiled: {
                files: [{
                    cwd: transpiledDirectory,
                    src: [
                        "**/*.js",
                        "**/*.js.map"
                    ],
                    dest: compiledDirectory
                }],
                compareUsing: "md5"
            },
            /**
             * Copy the test source files into the test-classes target directory.
             */
            test: {
                files: testInputDirs.map(function (inputDirectory) {
                    return {
                        cwd: inputDirectory,
                        src: ["**"],
                        dest: testClassesDirectory
                    };
                }),
                verbose: true,
                compareUsing: "md5" // Avoids spurious syncs of touched, but otherwise unchanged, files (e.g. CSS)
            },
            /**
             * Copy the compiled files to the server deploy directory.
             */
            server: {
                files: [{
                    cwd: compiledDirectory,
                    src: ["**"],
                    dest: serverDeployDirectory
                }],
                verbose: true,
                compareUsing: "md5" // Avoids spurious syncs of touched, but otherwise unchanged, files (e.g. CSS)
            }
        },
        watch: {
            /**
             * Redeploy whenever any source files change.
             */
            source: {
                files: watchCompositionDirs.concat(testWatchDirs).map(function (dir) {
                    return dir + "/**";
                }),
                tasks: ["deploy"]
            }
        }
    });

    grunt.loadNpmTasks("grunt-babel");
    grunt.loadNpmTasks("grunt-contrib-copy");
    grunt.loadNpmTasks("grunt-contrib-less");
    grunt.loadNpmTasks("grunt-contrib-requirejs");
    grunt.loadNpmTasks("grunt-contrib-watch");
    grunt.loadNpmTasks("grunt-eslint");
    grunt.loadNpmTasks("grunt-karma");
    grunt.loadNpmTasks("grunt-newer");
    grunt.loadNpmTasks("grunt-sync");
    grunt.loadNpmTasks("grunt-text-replace");

    /**
     * Resync the compiled directory and deploy to the web server.
     */
    grunt.registerTask("deploy", [
        "sync:compose",
        "newer:babel",
        "less",
        "replace",
        "sync:compiled",
        "sync:transpiled",
        "sync:test",
        "sync:server"
    ]);

    /**
     * Fail loudly when a build composition source is missing.
     *
     * grunt-contrib-copy ignores a missing "cwd" SILENTLY. Without this check, a composition
     * source that failed to arrive produces a build that looks fine until requirejs:compile
     * fails much later for an unrelated-looking reason, or - worse - one that succeeds while
     * quietly shipping an incomplete /XUI. The npm-installed sources are the fragile ones: they
     * are installed with --no-save, so any bare `npm install` prunes them and nothing in
     * package.json records that they are expected.
     *
     * Registered for "build" only. The "dev"/watch path composes watchCompositionDirs from
     * FORGEROCK_UI_SRC, which is a different list with different preconditions.
     */
    grunt.registerTask("check-composition-sources", function () {
        var missing = buildCompositionDirs.filter(function (dir) {
            return !grunt.file.isDir(dir);
        });
        if (missing.length) {
            grunt.fail.fatal(
                "Missing build composition source(s):\n  " + missing.join("\n  ") +
                "\n\nThe commons sources arrive via Maven + npm. Build them first:\n" +
                "  mvn install -f <commons checkout>/ui/pom.xml  (produces the tgz:npm artifacts)\n" +
                "  mvn -DskipTests package                       (from openam-ui OR from here: task\n" +
                "                                                 4.8 removed the aggregator-only\n" +
                "                                                 plugin, and a standalone build\n" +
                "                                                 from this directory was verified)\n\n" +
                "A bare `npm install` here prunes the commons packages, which are installed with\n" +
                "the no-save flag; re-run the Maven build to restore them.\n\n" +
                "target/npm-libs is different: it is staged from node_modules by the VITE build\n" +
                "(task 4.7). If only that one is missing, run `npm run build:production` once."
            );
        }
    });

    /**
     * Rebuild the compiled directory. Maven then packs this directory into the final archive artefact.
     */
    grunt.registerTask("build", [
        "check-composition-sources",
        "copy:compose",
        "eslint",
        "babel",
        "copy:libraries",
        "requirejs",
        "less",
        "replace",
        "copy:compiled",
        "copy:transpiled"
    ]);

    grunt.registerTask("dev", ["copy:compose", "babel", "deploy", "watch"]);
    grunt.registerTask("prod", ["build"]);

    grunt.registerTask("default", ["dev"]);
};
