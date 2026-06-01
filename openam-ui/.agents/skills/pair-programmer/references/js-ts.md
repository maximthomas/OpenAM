# JavaScript / TypeScript Reference — Pair Programmer

## TypeScript First Principles

**Enable strict mode — always:**
```json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true
  }
}
```

**Prefer `unknown` over `any`:**
```typescript
function parse(input: unknown): string {
  if (typeof input !== "string") throw new TypeError("expected string");
  return input;
}
```

**Use discriminated unions instead of optional fields:**
```typescript
// Avoid
type Result = { success: boolean; value?: string; error?: Error };

// Prefer
type Result =
  | { success: true; value: string }
  | { success: false; error: Error };
```

**`as const` for literal types and enums:**
```typescript
const ROLES = ["admin", "user", "guest"] as const;
type Role = typeof ROLES[number]; // "admin" | "user" | "guest"
```

---

## Async / Promises

**Always `await` — never fire-and-forget without error handling:**
```typescript
// Bad: error silently swallowed
someAsyncTask();

// Good: at minimum
someAsyncTask().catch(logger.error);

// Best: await in async context
await someAsyncTask();
```

**`Promise.all` for concurrent independent work:**
```typescript
const [users, products] = await Promise.all([
  fetchUsers(),
  fetchProducts(),
]);
```

**`Promise.allSettled` when partial failure is acceptable:**
```typescript
const results = await Promise.allSettled([task1(), task2()]);
for (const r of results) {
  if (r.status === "rejected") logger.error(r.reason);
}
```

**Abort signals for cancellable async:**
```typescript
async function fetchData(signal: AbortSignal) {
  const res = await fetch(url, { signal });
  return res.json();
}
```

---

## Common JavaScript Traps

**`==` vs `===` — always use `===`:**
```javascript
null == undefined  // true  (loose)
null === undefined // false (strict)
0 == ""           // true  — never intended
```

**`typeof null === "object"` — this is a language bug:**
```typescript
function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null;
}
```

**Floating point:**
```javascript
0.1 + 0.2 === 0.3 // false — never compare floats with ===
Math.abs((0.1 + 0.2) - 0.3) < Number.EPSILON // correct
```

**Array holes vs empty values:**
```javascript
const a = [1, , 3]; // hole at index 1 — avoid entirely
const b = [1, undefined, 3]; // explicit undefined
```

**`this` binding — lost in callbacks:**
```typescript
class Timer {
  start() {
    // Bad: `this` is lost
    setTimeout(function() { this.stop(); }, 1000);
    
    // Good: arrow function captures lexical `this`
    setTimeout(() => { this.stop(); }, 1000);
  }
}
```

**Mutating props/state (React):**
```typescript
// Bad
state.items.push(newItem);
setState(state);

// Good
setState({ ...state, items: [...state.items, newItem] });
```

---

## Modern JS Patterns

**Optional chaining and nullish coalescing:**
```typescript
const name = user?.profile?.name ?? "Anonymous";
user?.notify?.(); // safe method call
```

**Destructuring with defaults:**
```typescript
const { name = "default", age = 0 } = config;
const [first, ...rest] = items;
```

**Object spread for immutable updates:**
```typescript
const updated = { ...original, key: newValue };
```

**Generators for lazy sequences:**
```typescript
function* range(start: number, end: number) {
  for (let i = start; i < end; i++) yield i;
}
```

---

## Error Handling

**Never swallow errors silently:**
```typescript
try {
  await riskyOp();
} catch (err) {
  // at minimum: log and rethrow, or convert to domain error
  logger.error("riskyOp failed", { err });
  throw new ServiceError("operation failed", { cause: err });
}
```

**Use `Error` objects, not strings:**
```typescript
throw new Error("something went wrong"); // has stack trace
throw "something went wrong";            // no stack trace — avoid
```

**Result types for expected failure (no exceptions for control flow):**
```typescript
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

function parseId(s: string): Result<number> {
  const n = parseInt(s, 10);
  if (isNaN(n)) return { ok: false, error: new Error(`invalid id: ${s}`) };
  return { ok: true, value: n };
}
```

---

## Node.js Specifics

**Environment variables:**
```typescript
const port = parseInt(process.env.PORT ?? "3000", 10);
// Validate at startup — don't discover missing vars at runtime
```

**Stream large data — don't buffer:**
```typescript
// Bad: loads entire file into memory
const data = await fs.readFile(bigFile);

// Good: stream
const stream = fs.createReadStream(bigFile);
for await (const chunk of stream) { process(chunk); }
```

**Graceful shutdown:**
```typescript
process.on("SIGTERM", async () => {
  await server.close();
  await db.disconnect();
  process.exit(0);
});
```

---

## React-Specific

**Avoid stale closures in effects:**
```typescript
useEffect(() => {
  const id = setInterval(() => {
    // `count` will be stale if not in deps
    setCount(c => c + 1); // functional update avoids stale closure
  }, 1000);
  return () => clearInterval(id);
}, []); // empty deps is intentional here
```

**Don't derive state that can be computed:**
```typescript
// Bad: redundant state
const [items, setItems] = useState([...]);
const [count, setCount] = useState(0); // redundant

// Good: derive count
const count = items.length;
```

**Keys must be stable and unique — never use index as key for reorderable lists.**

---

## Security

- **XSS:** Never `dangerouslySetInnerHTML` with user content. Sanitize with `DOMPurify` if necessary.
- **Prototype pollution:** Validate object shapes before merging untrusted input (`Object.assign`, spread operators)
- **`eval()` / `new Function()`:** Never with user input
- **CORS:** Set explicitly — don't use `*` in production for credentialed requests
- **Content Security Policy:** Set via headers, not meta tags
- **npm:** Run `npm audit` in CI. Pin dependencies with a lockfile.
- **Regex DoS (ReDoS):** Avoid backtracking-prone regexes on user input (e.g., `/(a+)+$/`)
