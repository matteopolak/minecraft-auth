# Minecraft Auth

```powershell
# Install with yarn
yarn add @matteopolak/minecraft-auth

# Install with npm
npm install @matteopolak/minecraft-auth
```

## Usage

```typescript
import { MicrosoftAuth } from '@matteopolak/minecraft-auth';

const auth = new MicrosoftAuth('username', 'password');
const java = await auth.getJavaToken();

console.log(java.token); // eyJhbG...
```
