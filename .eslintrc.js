module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    'eslint:recommended',
  ],
  plugins: ['@typescript-eslint'],
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  env: {
    node: true,
    es6: true,
  },
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/no-explicit-any': 'off', // Allow any for flexibility
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-non-null-assertion': 'off', // Allow non-null assertions
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-case-declarations': 'off', // Allow declarations in case blocks
    'no-undef': 'off', // TypeScript handles this
  },
  ignorePatterns: ['dist/', 'node_modules/', 'native/'],
};