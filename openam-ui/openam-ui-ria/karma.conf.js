module.exports = function (config) {
    config.set({
        client: {
            mocha: {
                timeout : 6000
            }
        },
        basePath: ".",
        frameworks: ["mocha", "requirejs"],
        files: [
            { pattern: "target/test-classes/test-main.js" },
            { pattern: "target/test-classes/**/*.js", included: false },
            // Since task 4.7 this also carries libs/: the runtime libraries are staged from
            // npm and copied into the build output, where they used to be read out of
            // target/dependencies/libs. That pattern is gone, and since task 4.8 so is the
            // directory: CodeMirror was the last thing in it and is an npm dependency now. The
            // harness loads the bytes the build actually ships.
            { pattern: "target/compiled/**/*.js", included: false },
            { pattern: "node_modules/chai/chai.js", included: false },
            { pattern: "node_modules/sinon-chai/lib/sinon-chai.js", included: false },
            // Replacing the commons.ui.libs sinon and squire test artifacts, which the removed
            // copy-dependencies-test execution used to place in target/test-classes/libs.
            { pattern: "node_modules/sinon/pkg/sinon.js", included: false },
            { pattern: "node_modules/squirejs/src/Squire.js", included: false }
        ],
        exclude: [],
        preprocessors: {
            "target/test-classes/org/**/*.js": ["babel"],
            "target/test-classes/store/**/*.js": ["babel"]
        },
        babelPreprocessor: {
            options: {
                ignore: ["libs/"],
                presets: [["@babel/preset-env", { "targets": "> 0.2%, not dead, last 2 versions" }],]
            }
        },
        reporters: ["progress"],
        port: 9876,
        colors: true,
        logLevel: config.LOG_INFO,
        autoWatch: true,
        browsers: ["chromeNoSandbox"],
        customLaunchers: {
            chromeNoSandbox: {
                base: "Chrome",
                flags: ["--headless=new",
                    "--allow-file-access-from-files",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox"]
            }
        },
        singleRun: false,
        browserNoActivityTimeout: 60000
    });
};
