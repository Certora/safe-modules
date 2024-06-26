module.exports = {
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  extends: ['../../.eslintrc.js', 'plugin:react-hooks/recommended'],
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      {
        allowExportNames: ['meta', 'links', 'headers', 'loader', 'action'],
        allowConstantExport: true,
      },
    ],
  },
};
