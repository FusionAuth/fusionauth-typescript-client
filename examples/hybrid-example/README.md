FusionAuth Client Hybrid Example
====

This example exists as a minimal setup to get the FusionAuth Client working in both the browser and nodejs environment. For web publishing we chose to go with `browserify` for simplicity. This could also be done using webpack if preferred.

## Requirements

* `browserify` - Compiles stuff for the browser
* `tsify` - Compiles typescript for browserify
* `browserify-shim` - Allows code to work in both the browser and node by replacing require(x) with require(y)
* `typescript` - tsify doesn't depend on typescript so that you can choose exactly which version you want
* `tsconfig.json` - Provides the rules for `tsc` and `tsify` to compile typescript, we provided a minimal example.
* `example.ts` - A script that actually uses FusionAuth client
* `index.html` - A webpage that uses the script

## Building

To build nodejs you will need to use `tsc`. This compiles the project to `build/example.js` and produces a sourcemap. You can then run this in nodejs.

To build for the browser we use `npx browserify example.ts --debug -p tsify -t browserify-shim -o dist/example-browser.js` but we also add this line of code to package.json so that you can instead just call `npm run build-browser`. Both of these commands outputs to `dist/example-browser.js`. This example currently uses a browserify-shim for the client itself to replace the node version with the browser version we ship. This also means that the client must be added to the index.html as a `<script>` as well. In the future you will be able to omit this, and your code will be merged with the client code into one monolithic script.
