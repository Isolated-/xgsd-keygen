# Key Generation for xGSD

## Installation

Install this library with yarn or npm:

```sh
# yarn
yarn add xgsd-keygen

# npm
npm install xgsd-keygen
```

## Tests

Commands:

- `test`: runs test runner
- `test:cov`: runs test runner and generates coverage reports

## Usage

Using this library is super simple (and opinionated), example usage:

```ts
// import the function
import { generateMasterKey } from "xgsd-keygen";

const masterKey = await generateMasterKey("Passphrase1234!");
// masterKey.key is a Hexidecimal string, mnemonic will contain 12 words
```

## Notice

This package is publicly available in compliance with Make Data Mine Again 2025 (our internal policy at Myked and xGSD). We cannot offer support or maintainence outside of our project.
