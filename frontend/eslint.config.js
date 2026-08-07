import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    plugins: {
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // A <button> with no type defaults to type="submit", which silently
      // submits any form it later gets nested in. Prefer the Button component
      // from @/components/ui (it defaults to type="button"); when a raw
      // element is needed, state the type. eslint-plugin-react's
      // button-has-type would cover this, but it isn't a dependency.
      'no-restricted-syntax': ['error',
        {
          selector: 'JSXOpeningElement[name.name="button"]:not(:has(JSXAttribute[name.name="type"]))',
          message: 'Add an explicit type to <button> (type="button" unless it submits a form).',
        },
        // scope="col" associates a header with its column for screen readers.
        // jsx-a11y has no rule for this, and every table in the app relies on
        // it, so enforce it here.
        {
          selector: 'JSXOpeningElement[name.name="th"]:not(:has(JSXAttribute[name.name="scope"]))',
          message: 'Add scope="col" (or scope="row") to <th> for table semantics.',
        },
      ],
    },
  },
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
)
