<p align="center">
  <img src="https://blockstack.org/images/resources/browser-home-screen@2x.png" alt="Blockstack Browser screenshot" width="686" height="306">
</p>

# Blockstack Browser [![CircleCI](https://img.shields.io/circleci/project/blockstack/blockstack-browser/master.svg)](https://circleci.com/gh/blockstack/blockstack-browser/tree/master) [![License](https://img.shields.io/github/license/blockstack/blockstack-browser.svg)](https://github.com/blockstack/blockstack-browser/blob/master/LICENSE.md) [![Slack](https://img.shields.io/badge/join-slack-e32072.svg?style=flat)](http://slack.blockstack.org/)

The Blockstack Browser allows you to explore the Blockstack internet.

## Table of contents

- [Releases](#releases)
- [Developing](#developing)
- [Building for macOS](#building-for-macos)
- [Building for the Web](#building-for-the-web)
- [Contributing](#contributing)
- [Logging](#logging)
- [Tech Stack](#tech-stack)
- [Testing](#testing)

## Releases

[Download the latest release](https://github.com/blockstack/blockstack-browser/releases)

## Developing

Blockstack Browser requires a local instance of Blockstack Core to run. To get started, first install Blockstack Core and then proceed with the installation of Blockstack Browser.

### macOS

Blockstack for macOS contains a Blockstack Core API endpoint & a CORS proxy.

*Please note these instructions have only been tested on macOS 10.13*

1. Download and install the [latest release of Blockstack for Mac](https://github.com/blockstack/blockstack-browser/releases).
1. Start Blockstack
1. Option-click the Blockstack menu bar item and select "Enable Development Mode"
1. Clone this repo: `git clone https://github.com/blockstack/blockstack-browser.git`
1. Install node dependencies: `npm install`
1. Click the Blockstack menu bar item and select "Copy Core API password"
1. Run `npm run dev`
1. When prompted in your browser, enter the Core API password and click save.


### Linux

#### Part 1: Install & configure Blockstack Core

1. Install [Blockstack Core](https://github.com/blockstack/blockstack-core). Please follow the instructions in Blockstack Core's repository.
1. Setup the Blockstack Core wallet: `blockstack setup`. You will be prompted to select a wallet password. *Skip this step if you already have a Core wallet*
1. Start the Blockstack Core API: `blockstack api start --api_password <core-api-password> --password <wallet-password>` where `<core-api-password>` is a String value you select and `<wallet-password>` is the wallet password you selected previously.
1. Make sure there's a local Blockstack Core API running by checking `http://localhost:6270/v1/names/blockstack.id` to see if it returns a response.

#### Part 2: Install Blockstack Browser

1. Clone this repo: `git clone https://github.com/blockstack/blockstack-browser.git`
1. Install node dependencies: `npm install`
1. Run `npm run dev-proxy` to start the CORS proxy
1. Run `npm run dev`
1. When prompted in your browser, enter the Core API password you selected in part 1.


*Note: npm dev runs a BrowserSync process that watches the assets in `/app`, then builds them and places them in `/build`, and in turn serves them up on port 3000. When changes are made to the original files, they are rebuilt and re-synced to the browser frames you have open.*


### Windows

*Note: The installation instructions below are for setting up a development environment on Windows 10. If you are using Blockstack for the first time or are looking to try Blockstack out, please go to our [downloads page](https://blockstack.org/install) and install the version there.*

The Blockstack API and the Blockstack Browser run best in Docker. There is a provided CLI to help you build and launch `docker` images if you are not comfortable with `docker`:`launcher`. The CLI will pull down the images from our [Quay image repository](https://quay.io/organization/blockstack).

1. Download the [launcher script](https://raw.githubusercontent.com/blockstack/packaging/master/browser-core-docker/launcher) from our packaging repository.

2. In order to use the launcher script, you must have Docker installed and setup on your machine. Our [Windows installer](http://packages.blockstack.com/repositories/windows/) sets up Docker for you and uses the launcher script to start Blockstack Browser automatically. The same Windows installer can be found on the [Installing Blockstack README](https://github.com/blockstack/blockstack-core#installing-blockstack).

3. Run `./launcher pull`. This will fetch the latest docker images from our image repository.

4. Start the Blockstack Core API using `./launcher start`. This will start the Blockstack browser and a paired `blockstack-api` daemon. The first time you run this, it will create a `$HOME/.blockstack` directory to store your Blockstack Core API configuration and wallet. You will also need to create a password to protect these configurations.

5. When you are done, you can clean up your environment: `./launcher stop`


## Building for macOS

1. Make sure you have a working installation of Xcode 9 or higher & valid Mac Developer signing certificate
1. Make sure you have an OpenSSL ready for bottling by homebrew by running `brew install openssl --build-bottle`
1. Make sure you have `hg` installed by running `brew install hg`
1. Run `npm install nexe -g` to install the "node to native" binary tool globally
1. Open the Blockstack macOS project in Xcode and configure your code signing development team (You only need to do this once)
1. Run `npm run mac` to build a debug release signed with your Mac Developer certificate

*Note: You only need to run `nexe` once but the first build will take a while as `nexe` downloads and compiles a source copy of node. Then it creates and copies the needed proxy binaries into place and copies a built version of the browser web app into the source tree.*

*Note: This has only been tested on macOS High Sierra 10.13*

### Building a macOS release for distribution

1. Ensure you have valid Developer ID signing credentials in your Keychain. (See https://developer.apple.com/developer-id/ for more information)
1. Follow the instructions in the above section for building for macOS.
1. Open the Blockstack macOS project in Xcode.
1. Select the Product menu and click Archive.
1. When the archive build completes, the Organizer window will open. Select your new build.
1. Click "Export..."
1. Click "Export a Developer ID-signed Application"
1. Choose the development team with the Developer ID you'd like to use to sign the application.
1. Click "Export" and select the location to which you would like to save the signed build.


## Building for the Web

1. Make sure you've cloned the repo and installed all npm assets (as shown above)
1. Run `npm run web`


## Contributing

We do project-wide sprints every two weeks and we're always looking for more help.

If you'd like to contribute, head to the [contributing guidelines](/CONTRIBUTING.md). Inside you'll find directions for opening issues, coding standards, and notes on development.

## Logging

The Browser uses `log4js` for logging. The macOS app uses macOS's unified logging
API, `os_log` for logging.

### macOS

On macOS, the Browser sends log events to the macOS
app's log server. These are then included in macOS's unified logging API. You
can view logs by starting `Console.app`.

To see only `Blockstack` process logs, filter by process by
typing `process: Blockstack` in the search box. You can also filter for only log
entries proactively generated by the BLockstack project using this query:
`subsystem:org.blockstack.portal subsystem:org.blockstack.core subsystem:org.blockstack.mac`
If you'd like to see more detail, enable the inclusion
of Info and Debug messages in the Action menu. Please note that in our experience,
`Console.app` doesn't always show debug messages in real time and only shows them
when doing a log dump as described below.

#### Sending logs to developers

Blockstack logs are included in macOS's unified logging system. This allows
us to easily collect a large amount of information about the user's system when
we need to troubleshoot a problem while protecting their privacy.

1. Press Shift-Control-Option-Command-Period. Your screen will briefly flash.
2. After a few minutes, a Finder window will automatically open to `/private/var/tmp`
3. Send the most recent `sysdiagnose_DATE_TIME.tar.gz` file to your friendly developers.

The most important file in this archive is `system_logs.logarchive`, which will
include recent system logs including Blockstack's logs. You can open it on
a Mac using `Console.app`. The other files include information about your computer
that may help in diagnosing problems.

If you're worried about inadvertently sending some private information,
you can select the log entries you'd like to send inside `Console.app` and copy
them into an email or github issue. To help us debug your problem, we ask that
at a minimum you enable Info and Debug messages and filter by `process: Blockstack`.

More technical users (with admin permission) can use the `sysdiagnose` command
to generate a custom dump of information.

## Tech Stack

This app uses the latest versions of the following libraries:

- [React Rocket Boilerplate](https://github.com/jakemmarsh/react-rocket-boilerplate)
- [ReactJS](https://github.com/facebook/react)
- [React Router](https://github.com/rackt/react-router)
- [RefluxJS](https://github.com/spoike/refluxjs)
- [Gulp](http://gulpjs.com/)
- [Browserify](http://browserify.org/)
- [Redux](https://github.com/reactjs/redux)
- [Babel](https://github.com/babel/babel)

Along with many Gulp libraries (these can be seen in either `package.json`, or at the top of each task in `/gulp/tasks/`).


## Testing

1. If you haven't already, follow steps 1 & 2 above
2. If you haven't already run `npm run dev` or `npm run build` at least once, run `npm run build`
3. Run all tests in the `tests/` directory with the `npm run test` command
  * A single file can be run by specifing an `-f` flag: `npm run test -f <PATH_TO_TEST_FILE>`
    * In the `PATH_TO_TEST_FILE`, it is possible to omit the `tests/` prefix, as well as the `.test.js` suffix. They will be automatically added if not detected.

*Note: When running tests, code coverage will be automatically calculated and output to an HTML file using the [Istanbul](https://github.com/gotwarlost/istanbul) library. These files can be seen in the generated `coverage/` directory.*

## App Development
### Run the browser in the Blockstack Test Environment

When developing apps, the browser can be run in a docker test environment that is backed by the regtest bitcoin network, hence no real money involved. 

The easiest way to get that setup is through docker containers for the api, the browser and the cors-proxy. There is a  [docker-compose.yaml file](https://github.com/blockstack/blockstack-todos/blob/master/docker-compose.yaml) published in the Blockstack todo app repo that does this. To use it, first [install Docker](https://docs.docker.com/engine/installation/) and stop any running Blockstack applications (blockstack-browser or blockstack api) then:

```
$ docker-compose up -d
```

This brings up 
1. a `blockstack-core api` node that is backed 
   * by a `bitcoind` instance running **regtest** and 
   * by a [`blockstack-core`](https://github.com/blockstack/blockstack-core) node built from the test chain. 
   
   The initialization script generates 50 BTCs for the core wallet.
1. a blockstack-browser node. It uses bitcoin addresses that are mapped to regtest bitcoin addresses. 
1. a [cors-proxy](https://www.npmjs.com/package/corsproxy) to bypass origin policy issues.

The easiest way to work with this setup is in **Incognito mode** in your browser. Once the images have been pulled down and the containers are started you can open http://localhost:8888. 

Choose the Advanced Mode setup and enter the API Password as `blockstack_integration_test_api_password`

### Common Tasks
* You can send bitcoins from the core wallet to the browser wallet by opening the hidden url [http://localhost:8888/wallet/send-core](http://localhost:8888/wallet/send-core)

* You can inspect the mapped bitcoin addresses from the browser node to the regtest address by looking into the log file of the api node (execute `bash` in the api container and look at /tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.portal_test_env/client/api_endpoint.log). 

* You can inspect the api password by looking into the client.ini file of the api node (execute `bash` in the api container and look at /tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.portal_test_env/client/client.ini)

* You can verify the blockstack version of the api node by running `curl localhost:6270/v1/node/ping`
