# KubeChat Web Application

## Quick Start

```bash
# Install dependencies
pnpm install

# Start development server (ALWAYS runs on port 3001)
pnpm dev

# Build for production
pnpm build

# Run tests
pnpm test
```

## 🚨 IMPORTANT: Port Configuration

**This application ALWAYS runs on port 3001**

- **Development Server**: `http://localhost:3001`
- **Do NOT use port 3000** - The application is configured to use port 3001 exclusively
- If port 3001 is in use, the dev server will fail with `strictPort: true` configuration
- Make sure to bookmark and share `http://localhost:3001` with team members

## Available Scripts

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start development server on port 3001 |
| `pnpm build` | Build for production |
| `pnpm test` | Run unit tests |
| `pnpm test:coverage` | Run tests with coverage |
| `pnpm lint` | Run ESLint |
| `pnpm lint:fix` | Fix ESLint issues |
| `pnpm format` | Format code with Prettier |
| `pnpm type-check` | Run TypeScript type checking |
| `pnpm preview` | Preview production build |

## Tech Stack

- **React 19.1.1** - UI library
- **TypeScript 5.8.3** - Type safety
- **Vite 7.1.2** - Build tool and dev server
- **Tailwind CSS 3.4** - Styling
- **Radix UI** - Accessible components
- **Zustand 5.0.8** - State management
- **Vitest 3.2.4** - Testing framework

## Project Structure

```
web/
├── src/
│   ├── components/       # React components
│   ├── contexts/         # React contexts
│   ├── hooks/           # Custom React hooks
│   ├── stores/          # Zustand stores
│   ├── types/           # TypeScript type definitions
│   ├── utils/           # Utility functions
│   └── main.tsx         # Application entry point
├── public/              # Static assets
├── dist/               # Production build output
└── package.json        # Dependencies and scripts
```

## Development Notes

- The application uses **strict TypeScript** configuration
- All components must be **accessible** (WCAG AA compliant)
- **WebSocket** connection for real-time chat functionality
- **Authentication** system with JWT token support
- **Conversation history** with search and export features

## Team Guidelines

⚠️ **Remember: Always use port 3001 for development**
- Bookmark: `http://localhost:3001`
- Share this port with team members
- Report any issues with port 3001 immediately

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable
type-aware lint rules:

```js
export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      ...tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      ...tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      ...tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
]);
```

You can also install
[eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x)
and
[eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom)
for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x';
import reactDom from 'eslint-plugin-react-dom';

export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
]);
```
