// jest.config.js
import { createDefaultPreset } from "ts-jest";

/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm", // for ESM support
  testEnvironment: "node",
  transform: {
    ...createDefaultPreset().transform,
  },
  extensionsToTreatAsEsm: [".ts"], // make sure ts files are treated as ESM
};
