FusionAuth Client NodeJS Example
====

This example exists as a minimal setup to get the FusionAuth Client working in the nodejs environment. 

## Requirements

* `typescript` - We use typescript in this example for type completion while we code
* `tsconfig.json` - Provides the rules for `tsc` to compile typescript, we provided a minimal example
* `example.ts` - A script that actually uses FusionAuth client

## Building

To build nodejs you will need to use `tsc`. This compiles the project to `build/example.js` and produces a sourcemap. You can then run this in nodejs.

Assuming you have node but not typescript installed, you can do the following (tested with node v12):

* `sudo npm install -g typescript # will install the `tsc` executable.`
* `npm install @types/node --save-dev # solves the 'Build:Cannot find type definition file for 'node'' issue`
* update the api key and FA location in `example.ts`
* `tsc # compiles the typescript`
* `node build/example.js # actually runs the code`

