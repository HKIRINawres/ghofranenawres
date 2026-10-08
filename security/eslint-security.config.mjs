// ESLint config of the eslint-security pre-commit hook (brief §3): eslint-plugin-security rules only,
// without type information, so a commit is checked in seconds (the project config is type-aware and
// takes minutes). The editor shows the same rules live, through eslint.config.mjs.
import pluginSecurity from 'eslint-plugin-security'
import tseslint from 'typescript-eslint'

export default [
  // test/ does not ship (a Cypress test solves the captcha with eval); secrets there are still scanned
  { ignores: ['data/static/codefixes/**', 'test/**', 'build/**', 'dist/**', 'frontend/dist/**', '**/node_modules/**'] },
  // parser + plugin only (no rules), so `eslint-disable @typescript-eslint/...` comments stay valid
  { files: ['**/*.ts'], ...tseslint.configs.base },
  { linterOptions: { reportUnusedDisableDirectives: 'off' } },
  pluginSecurity.configs.recommended,
  {
    rules: {
      // These block the commit: in this code base they only match real flaws (2 eval calls on
      // user input, routes/captcha.ts and routes/userProfile.ts). The other rules stay warnings.
      'security/detect-eval-with-expression': 'error',
      'security/detect-child-process': 'error',
      'security/detect-new-buffer': 'error',
      'security/detect-pseudoRandomBytes': 'error',
      'security/detect-bidi-characters': 'error',
      'security/detect-disable-mustache-escape': 'error',
      // 1432 hits, nearly all obj[key] with a trusted key: noise that would hide the real findings
      'security/detect-object-injection': 'off'
    }
  }
]
