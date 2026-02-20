/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/server.ts',
    '!src/db/migrate.ts',
    '!src/utils/generate-cert.ts',
  ],
  coverageThreshold: {
    global: {
      branches: 20,
      functions: 30,
      lines: 35,
      statements: 35,
    },
  },
  setupFiles: ['<rootDir>/tests/setup.ts'],
  testTimeout: 30000,
};
