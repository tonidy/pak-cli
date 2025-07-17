module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: false,
    }],
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/cli.ts', // Exclude CLI from coverage
  ],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  setupFilesAfterEnv: [],
  testTimeout: 20000, // Increase timeout for crypto operations
  // Ignore the native addon, dist files, and existing test directory (uses Mocha)
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/native/',
    '/test/', // Exclude existing Mocha tests
  ],
};